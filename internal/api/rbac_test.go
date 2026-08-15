package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

const (
	tokViewer      = "tok_v"
	tokScanner     = "tok_s"
	tokRemediator  = "tok_r"
	tokVaultImport = "tok_i"
	tokApprover    = "tok_a"
	tokPlatform    = "tok_p"
	tokInventory   = "tok_inv"
	tokUnknownRole = "tok_unknown_role"
)

func rbacTokens() map[string]string {
	return map[string]string{
		roleViewer:           tokViewer,
		roleScannerOperator:  tokScanner,
		roleRemediator:       tokRemediator,
		roleVaultImportAdmin: tokVaultImport,
		roleApprover:         tokApprover,
		rolePlatformAdmin:    tokPlatform,
		roleInventory:        tokInventory,
		"not_a_role":         tokUnknownRole,
	}
}

type recordingAuditor struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *recordingAuditor) AppendAudit(_ context.Context, ev AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *recordingAuditor) denies() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, 0, len(a.events))
	for _, ev := range a.events {
		if ev.Decision == "deny" {
			out = append(out, ev)
		}
	}
	return out
}

type stubScanCreator struct{}

func (stubScanCreator) CreateScan(_ context.Context, cidrs, hostnames []string, ports []int, concurrency, maxPending int) (store.Scan, error) {
	return store.Scan{
		ID:          uuid.New(),
		Status:      "pending",
		CIDRs:       cidrs,
		Hostnames:   hostnames,
		Ports:       ports,
		Concurrency: concurrency,
	}, nil
}

func newRBACServer(t *testing.T) (*Server, *recordingAuditor) {
	t.Helper()
	aud := &recordingAuditor{}
	srv := newAuthServer(config.Config{StaticTokens: rbacTokens()})
	srv.auditor = aud
	srv.scans = stubScanCreator{}
	srv.resources = &fakeResourceStore{}
	srv.worker = nil
	return srv, aud
}

func doRBAC(srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	return rec
}

func TestRBAC_ViewerCannotPostScansEvenWithConsent(t *testing.T) {
	t.Parallel()

	srv, aud := newRBACServer(t)
	rec := doRBAC(srv, http.MethodPost, "/api/v1/scans", tokViewer, `{"consent":true,"cidrs":["10.0.0.0/24"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /scans consent:true status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(aud.denies()) == 0 {
		t.Fatal("403 must append an audit deny")
	}
}

func TestRBAC_ViewerConsentFalseIs403Not400(t *testing.T) {
	t.Parallel()

	srv, _ := newRBACServer(t)
	rec := doRBAC(srv, http.MethodPost, "/api/v1/scans", tokViewer, `{"consent":false,"cidrs":["10.0.0.0/24"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized role + consent:false status = %d, want 403 not 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestRBAC_ScannerOperatorScanConsent(t *testing.T) {
	t.Parallel()

	srv, _ := newRBACServer(t)

	noConsent := doRBAC(srv, http.MethodPost, "/api/v1/scans", tokScanner, `{"consent":false,"cidrs":["10.0.0.0/24"]}`)
	if noConsent.Code != http.StatusBadRequest {
		t.Fatalf("scanner_operator without consent status = %d, want 400 (body: %s)", noConsent.Code, noConsent.Body.String())
	}

	withConsent := doRBAC(srv, http.MethodPost, "/api/v1/scans", tokScanner, `{"consent":true,"cidrs":["10.0.0.0/24"]}`)
	if withConsent.Code != http.StatusAccepted && withConsent.Code != http.StatusOK {
		t.Fatalf("scanner_operator with consent status = %d, want 202 or 200 (body: %s)", withConsent.Code, withConsent.Body.String())
	}
}

func TestRBAC_ScannerOperatorCannotImportCA(t *testing.T) {
	t.Parallel()

	srv, aud := newRBACServer(t)
	id := uuid.New().String()
	rec := doRBAC(srv, http.MethodPost, "/api/v1/issuers/"+id+"/import", tokScanner, `{"consent":true,"mount":"pki"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scanner_operator CA import status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(aud.denies()) == 0 {
		t.Fatal("403 must append an audit deny")
	}
}

func TestRBAC_DeleteRequiresPlatformAdmin(t *testing.T) {
	t.Parallel()

	srv, aud := newRBACServer(t)
	id := uuid.New().String()

	for _, tok := range []string{tokViewer, tokScanner, tokRemediator, tokVaultImport, tokApprover, tokInventory} {
		rec := doRBAC(srv, http.MethodDelete, "/api/v1/scans/"+id, tok, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("DELETE /scans as token %q status = %d, want 403 (body: %s)", tok, rec.Code, rec.Body.String())
		}
	}
	if len(aud.denies()) == 0 {
		t.Fatal("403 must append an audit deny")
	}

	admin := doRBAC(srv, http.MethodDelete, "/api/v1/certificates/"+id, tokPlatform, "")
	if admin.Code == http.StatusForbidden || admin.Code == http.StatusUnauthorized {
		t.Fatalf("platform_admin DELETE must not be 401/403, got %d (body: %s)", admin.Code, admin.Body.String())
	}
}

func TestRBAC_UnknownRoleOrWrongToken401(t *testing.T) {
	t.Parallel()

	srv, aud := newRBACServer(t)

	wrong := doRBAC(srv, http.MethodGet, "/api/v1/certificates", "tok_unknown", "")
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401 (body: %s)", wrong.Code, wrong.Body.String())
	}

	unknownRole := doRBAC(srv, http.MethodGet, "/api/v1/certificates", tokUnknownRole, "")
	if unknownRole.Code != http.StatusUnauthorized {
		t.Fatalf("unknown role status = %d, want 401 (body: %s)", unknownRole.Code, unknownRole.Body.String())
	}

	if len(aud.denies()) == 0 {
		t.Fatal("401 must append an audit deny")
	}
}

func TestRBAC_UnauthorizedConsentTrueIs401(t *testing.T) {
	t.Parallel()

	srv, _ := newRBACServer(t)
	rec := doRBAC(srv, http.MethodPost, "/api/v1/scans", "", `{"consent":true,"cidrs":["10.0.0.0/24"]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token + consent:true status = %d, want 401 not 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestRBAC_InventoryRoleIsInventoryOnly(t *testing.T) {
	t.Parallel()

	srv, _ := newRBACServer(t)

	inv := doRBAC(srv, http.MethodGet, "/api/v1/inventory", tokInventory, "")
	if inv.Code == http.StatusForbidden || inv.Code == http.StatusUnauthorized {
		t.Fatalf("inventory GET /inventory must not be 401/403, got %d (body: %s)", inv.Code, inv.Body.String())
	}

	certs := doRBAC(srv, http.MethodGet, "/api/v1/certificates", tokInventory, "")
	if certs.Code != http.StatusForbidden {
		t.Fatalf("inventory GET /certificates status = %d, want 403 (body: %s)", certs.Code, certs.Body.String())
	}
}

func TestRoleAllows_PermissionMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role, method, path string
		want               bool
	}{
		{roleViewer, http.MethodGet, "/api/v1/certificates", true},
		{roleViewer, http.MethodGet, "/api/v1/scans", true},
		{roleViewer, http.MethodGet, "/api/v1/inventory", true},
		{roleViewer, http.MethodGet, "/api/v1/events", true},
		{roleViewer, http.MethodGet, "/api/v1/issuers", true},
		{roleViewer, http.MethodGet, "/api/v1/blindspot", true},
		{roleViewer, http.MethodGet, "/api/v1/compliance/summary", true},
		{roleViewer, http.MethodGet, "/api/v1/scans/" + uuid.New().String() + "/report", true},
		{roleViewer, http.MethodPost, "/api/v1/scans", false},
		{roleViewer, http.MethodDelete, "/api/v1/scans/" + uuid.New().String(), false},
		{roleViewer, http.MethodGet, "/api/v1/settings/connections", false},

		{roleApprover, http.MethodGet, "/api/v1/certificates", true},
		{roleApprover, http.MethodPost, "/api/v1/scans", false},
		{roleApprover, http.MethodPatch, "/api/v1/certificates/" + uuid.New().String(), false},

		{roleScannerOperator, http.MethodGet, "/api/v1/certificates", true},
		{roleScannerOperator, http.MethodPost, "/api/v1/scans", true},
		{roleScannerOperator, http.MethodPost, "/api/v1/issuers/" + uuid.New().String() + "/import", false},
		{roleScannerOperator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/renew", false},

		{roleRemediator, http.MethodPost, "/api/v1/scans", true},
		{roleRemediator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/catalog-import", true},
		{roleRemediator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/renew", true},
		{roleRemediator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/migrate", true},
		{roleRemediator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/revoke", true},
		{roleRemediator, http.MethodPost, "/api/v1/renew-expiring", true},
		{roleRemediator, http.MethodPost, "/api/v1/migrate-eligible", true},
		{roleRemediator, http.MethodPost, "/api/v1/lifecycle-jobs/claim", true},
		{roleRemediator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/revocation-check", true},
		{roleScannerOperator, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/migrate", false},
		{roleRemediator, http.MethodPatch, "/api/v1/certificates/" + uuid.New().String(), true},
		{roleRemediator, http.MethodGet, "/api/v1/settings/connections", true},
		{roleRemediator, http.MethodPut, "/api/v1/settings/connections", false},
		{roleRemediator, http.MethodPost, "/api/v1/issuers/" + uuid.New().String() + "/import", false},
		{roleRemediator, http.MethodDelete, "/api/v1/certificates/" + uuid.New().String(), false},

		{roleVaultImportAdmin, http.MethodPost, "/api/v1/issuers/" + uuid.New().String() + "/import", true},
		{roleVaultImportAdmin, http.MethodPost, "/api/v1/reconcile", true},
		{roleVaultImportAdmin, http.MethodPost, "/api/v1/certificates/" + uuid.New().String() + "/renew", true},
		{roleVaultImportAdmin, http.MethodDelete, "/api/v1/issuers/" + uuid.New().String(), false},
		{roleVaultImportAdmin, http.MethodGet, "/api/v1/settings/connections", false},

		{rolePlatformAdmin, http.MethodDelete, "/api/v1/scans/" + uuid.New().String(), true},
		{rolePlatformAdmin, http.MethodDelete, "/api/v1/certificates/" + uuid.New().String(), true},
		{rolePlatformAdmin, http.MethodDelete, "/api/v1/issuers/" + uuid.New().String(), true},
		{rolePlatformAdmin, http.MethodPut, "/api/v1/settings/connections", true},
		{rolePlatformAdmin, http.MethodPatch, "/api/v1/settings/connections", true},
		{rolePlatformAdmin, http.MethodPost, "/api/v1/settings/connections/test", true},
		{rolePlatformAdmin, http.MethodPost, "/api/v1/scans", true},

		{roleInventory, http.MethodGet, "/api/v1/inventory", true},
		{roleInventory, http.MethodGet, "/api/v1/certificates", false},
		{roleInventory, http.MethodPost, "/api/v1/scans", false},
	}
	for _, tt := range tests {
		t.Run(tt.role+" "+tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			got := roleAllows(tt.role, tt.method, tt.path)
			if got != tt.want {
				t.Fatalf("roleAllows(%q, %q, %q) = %v, want %v", tt.role, tt.method, tt.path, got, tt.want)
			}
		})
	}
}
