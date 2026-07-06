package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/revocation"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

type fakeImporter struct {
	result vault.IssuerImportResult
	err    error
}

func (f *fakeImporter) ImportIssuerBundle(context.Context, string, string) (vault.IssuerImportResult, error) {
	return f.result, f.err
}

type fakeResourceStore struct {
	scan             store.Scan
	scanErr          error
	cert             store.Certificate
	certErr          error
	certs            []store.Certificate
	listErr          error
	setStatusResult  store.Certificate
	setStatusErr     error
	issuer           store.Issuer
	issuerErr        error
	setIssuerRefErr  error
	issuerPEM        string
	issuerPEMErr     error
	markRevokedErr   error
	markRevokedN     int
	setRenewalErr    error
	gotRenewalConfig *store.RenewalConfig
	deleteScanErr    error
	deleteCertErr    error
	deleteIssuerErr  error
}

func (f *fakeResourceStore) GetCertificate(_ context.Context, _ uuid.UUID) (store.Certificate, error) {
	if f.certErr != nil {
		return store.Certificate{}, f.certErr
	}
	return f.cert, nil
}

func (f *fakeResourceStore) GetScan(_ context.Context, id uuid.UUID) (store.Scan, error) {
	if f.scanErr != nil {
		return store.Scan{}, f.scanErr
	}
	if f.scan.ID == uuid.Nil {
		f.scan.ID = id
	}
	return f.scan, nil
}

func (f *fakeResourceStore) ListCertificates(_ context.Context, filter store.CertificateFilter) ([]store.Certificate, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.certs, len(f.certs), nil
}

func (f *fakeResourceStore) SetManagedStatus(_ context.Context, _ uuid.UUID, status string) (store.Certificate, error) {
	if f.setStatusErr != nil {
		return store.Certificate{}, f.setStatusErr
	}
	c := f.setStatusResult
	c.ManagedStatus = status
	return c, nil
}

func (f *fakeResourceStore) SetRenewalConfig(_ context.Context, _ uuid.UUID, cfg store.RenewalConfig) (store.Certificate, error) {
	if f.setRenewalErr != nil {
		return store.Certificate{}, f.setRenewalErr
	}
	f.gotRenewalConfig = &cfg
	c := f.setStatusResult
	c.ManagedStatus = "imported"
	c.RenewalConfig = &cfg
	return c, nil
}

func (f *fakeResourceStore) GetIssuer(_ context.Context, _ uuid.UUID) (store.Issuer, error) {
	if f.issuerErr != nil {
		return store.Issuer{}, f.issuerErr
	}
	return f.issuer, nil
}

func (f *fakeResourceStore) SetIssuerVaultRef(_ context.Context, _ uuid.UUID, issuerRef, mount string) (store.Issuer, error) {
	if f.setIssuerRefErr != nil {
		return store.Issuer{}, f.setIssuerRefErr
	}
	i := f.issuer
	i.VaultIssuerRef = &issuerRef
	i.VaultPKIMount = &mount
	return i, nil
}

func (f *fakeResourceStore) GetIssuerPEMForCert(_ context.Context, _ string) (string, error) {
	return f.issuerPEM, f.issuerPEMErr
}

func (f *fakeResourceStore) MarkRevoked(_ context.Context, _ uuid.UUID, _ string) error {
	f.markRevokedN++
	return f.markRevokedErr
}

func (f *fakeResourceStore) DeleteScan(context.Context, uuid.UUID) error { return f.deleteScanErr }
func (f *fakeResourceStore) DeleteCertificate(context.Context, uuid.UUID) error {
	return f.deleteCertErr
}
func (f *fakeResourceStore) DeleteIssuer(context.Context, uuid.UUID) error { return f.deleteIssuerErr }

func newResourceServer(res resourceStore) *Server {
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.resources = res
	return srv
}

// idRequest builds a request carrying an "id" chi URL param.
func idRequest(method, id string) *http.Request {
	req := httptest.NewRequest(method, "/", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestHandleGetScan_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		id   string
		want int
	}{
		{name: "invalid id", res: &fakeResourceStore{}, id: "not-a-uuid", want: http.StatusBadRequest},
		{name: "not found", res: &fakeResourceStore{scanErr: store.ErrScanNotFound}, id: uuid.New().String(), want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{scanErr: context.Canceled}, id: uuid.New().String(), want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{scan: store.Scan{Status: "completed"}}, id: uuid.New().String(), want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetScan(rec, idRequest(http.MethodGet, tt.id))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleListScanCertificates_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "scan not found", res: &fakeResourceStore{scanErr: store.ErrScanNotFound}, want: http.StatusNotFound},
		{name: "scan db error", res: &fakeResourceStore{scanErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "list db error", res: &fakeResourceStore{listErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleListScanCertificates(rec, idRequest(http.MethodGet, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleGetCertificatePEM_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{certErr: store.ErrCertificateNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{certErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{cert: store.Certificate{PEM: "-----BEGIN CERTIFICATE-----"}}, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetCertificatePEM(rec, idRequest(http.MethodGet, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// handleGetCertificate's success path also reads observations from the concrete
// store, so only the lookup error paths are unit-testable via the seam.
func TestHandleGetCertificate_ErrorStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{certErr: store.ErrCertificateNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{certErr: context.Canceled}, want: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetCertificate(rec, idRequest(http.MethodGet, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleDeleteScan_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{deleteScanErr: store.ErrScanNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{deleteScanErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleDeleteScan(rec, idRequest(http.MethodDelete, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleDeleteCertificate_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{deleteCertErr: store.ErrCertificateNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{deleteCertErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleDeleteCertificate(rec, idRequest(http.MethodDelete, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleDeleteIssuer_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{deleteIssuerErr: store.ErrIssuerNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{deleteIssuerErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleDeleteIssuer(rec, idRequest(http.MethodDelete, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// idRequestBody builds a request carrying an "id" chi URL param and a JSON body.
func idRequestBody(method, id, body string) *http.Request {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestHandleCatalogImport_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		res             *fakeResourceStore
		id              string
		body            string
		want            int
		wantRenewalRole string
	}{
		{name: "invalid id", res: &fakeResourceStore{}, id: "nope", body: `{"consent":true}`, want: http.StatusBadRequest},
		{name: "bad body", res: &fakeResourceStore{}, id: uuid.New().String(), body: `{`, want: http.StatusBadRequest},
		{name: "no consent", res: &fakeResourceStore{}, id: uuid.New().String(), body: `{"consent":false}`, want: http.StatusBadRequest},
		{name: "not found", res: &fakeResourceStore{setStatusErr: store.ErrCertificateNotFound}, id: uuid.New().String(), body: `{"consent":true}`, want: http.StatusNotFound},
		{name: "managed in vault", res: &fakeResourceStore{setStatusErr: store.ErrManagedByVault}, id: uuid.New().String(), body: `{"consent":true}`, want: http.StatusConflict},
		{name: "db error", res: &fakeResourceStore{setStatusErr: context.Canceled}, id: uuid.New().String(), body: `{"consent":true}`, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, id: uuid.New().String(), body: `{"consent":true}`, want: http.StatusOK},
		{name: "success with renewal", res: &fakeResourceStore{}, id: uuid.New().String(), body: `{"consent":true,"renewal":{"role":"web-server","mount":"pki-int","service":"nginx"}}`, want: http.StatusOK, wantRenewalRole: "web-server"},
		{name: "renewal missing role", res: &fakeResourceStore{}, id: uuid.New().String(), body: `{"consent":true,"renewal":{"mount":"pki-int"}}`, want: http.StatusBadRequest},
		{name: "renewal ssti ttl", res: &fakeResourceStore{}, id: uuid.New().String(), body: `{"consent":true,"renewal":{"role":"web","mount":"pki","ttl":"{{ x }}"}}`, want: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleCatalogImport(rec, idRequestBody(http.MethodPost, tt.id, tt.body))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"imported"`) {
				t.Fatalf("expected managed_status imported in body: %s", rec.Body.String())
			}
			if tt.wantRenewalRole != "" {
				if tt.res.gotRenewalConfig == nil || tt.res.gotRenewalConfig.Role != tt.wantRenewalRole {
					t.Fatalf("renewal config not persisted: %+v", tt.res.gotRenewalConfig)
				}
			}
		})
	}
}

func TestHandleImportIssuer_Statuses(t *testing.T) {
	t.Parallel()

	ca := store.Issuer{IsCA: true, PEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"}
	okImporter := &fakeImporter{result: vault.IssuerImportResult{ImportedIssuers: []string{"iss-1"}}}

	tests := []struct {
		name     string
		res      *fakeResourceStore
		importer issuerImporter
		id       string
		body     string
		want     int
	}{
		{"invalid id", &fakeResourceStore{issuer: ca}, okImporter, "nope", `{"consent":true,"mount":"pki"}`, http.StatusBadRequest},
		{"bad body", &fakeResourceStore{issuer: ca}, okImporter, uuid.New().String(), `{`, http.StatusBadRequest},
		{"no consent", &fakeResourceStore{issuer: ca}, okImporter, uuid.New().String(), `{"consent":false,"mount":"pki"}`, http.StatusBadRequest},
		{"no mount", &fakeResourceStore{issuer: ca}, okImporter, uuid.New().String(), `{"consent":true}`, http.StatusBadRequest},
		{"invalid mount", &fakeResourceStore{issuer: ca}, okImporter, uuid.New().String(), `{"consent":true,"mount":"../../sys"}`, http.StatusBadRequest},
		{"vault not configured", &fakeResourceStore{issuer: ca}, nil, uuid.New().String(), `{"consent":true,"mount":"pki"}`, http.StatusServiceUnavailable},
		{"issuer not found", &fakeResourceStore{issuerErr: store.ErrIssuerNotFound}, okImporter, uuid.New().String(), `{"consent":true,"mount":"pki"}`, http.StatusNotFound},
		{"not a CA", &fakeResourceStore{issuer: store.Issuer{IsCA: false}}, okImporter, uuid.New().String(), `{"consent":true,"mount":"pki"}`, http.StatusConflict},
		{"vault error", &fakeResourceStore{issuer: ca}, &fakeImporter{err: errors.New("permission denied")}, uuid.New().String(), `{"consent":true,"mount":"pki"}`, http.StatusBadGateway},
		{"success", &fakeResourceStore{issuer: ca}, okImporter, uuid.New().String(), `{"consent":true,"mount":"pki"}`, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newResourceServer(tt.res)
			srv.importer = tt.importer
			rec := httptest.NewRecorder()
			srv.handleImportIssuer(rec, idRequestBody(http.MethodPost, tt.id, tt.body))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"vault_issuer_ref"`) {
				t.Fatalf("success body missing vault_issuer_ref: %s", rec.Body.String())
			}
		})
	}
}

func TestHandleGetCertificateChoose_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		id   string
		want int
	}{
		{"invalid id", &fakeResourceStore{}, "nope", http.StatusBadRequest},
		{"not found", &fakeResourceStore{certErr: store.ErrCertificateNotFound}, uuid.New().String(), http.StatusNotFound},
		{"db error", &fakeResourceStore{certErr: context.Canceled}, uuid.New().String(), http.StatusInternalServerError},
		{"success", &fakeResourceStore{cert: store.Certificate{ManagedStatus: "managed_in_vault"}}, uuid.New().String(), http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetCertificateChoose(rec, idRequest(http.MethodGet, tt.id))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"already_managed"`) {
				t.Fatalf("success body missing recommendation code: %s", rec.Body.String())
			}
		})
	}
}

func TestHandleRevocationCheck_Statuses(t *testing.T) {
	t.Parallel()

	revokedVerified := func(context.Context, revocation.CheckInput) (revocation.Result, error) {
		return revocation.Result{Status: revocation.StatusRevoked, Verified: true, Source: "ocsp"}, nil
	}
	revokedUnverified := func(context.Context, revocation.CheckInput) (revocation.Result, error) {
		return revocation.Result{Status: revocation.StatusRevoked, Verified: false, Source: "crl"}, nil
	}
	good := func(context.Context, revocation.CheckInput) (revocation.Result, error) {
		return revocation.Result{Status: revocation.StatusGood, Verified: true, Source: "ocsp"}, nil
	}
	checkErr := func(context.Context, revocation.CheckInput) (revocation.Result, error) {
		return revocation.Result{}, errors.New("fetch failed")
	}

	tests := []struct {
		name        string
		res         *fakeResourceStore
		check       revChecker
		id          string
		want        int
		wantPersist int
	}{
		{"invalid id", &fakeResourceStore{}, good, "nope", http.StatusBadRequest, 0},
		{"not found", &fakeResourceStore{certErr: store.ErrCertificateNotFound}, good, uuid.New().String(), http.StatusNotFound, 0},
		{"issuer lookup error", &fakeResourceStore{issuerPEMErr: context.Canceled}, good, uuid.New().String(), http.StatusInternalServerError, 0},
		{"crl check error", &fakeResourceStore{}, checkErr, uuid.New().String(), http.StatusBadGateway, 0},
		{"good no persist", &fakeResourceStore{}, good, uuid.New().String(), http.StatusOK, 0},
		{"revoked unverified advisory", &fakeResourceStore{}, revokedUnverified, uuid.New().String(), http.StatusOK, 0},
		{"revoked verified persists", &fakeResourceStore{}, revokedVerified, uuid.New().String(), http.StatusOK, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newResourceServer(tt.res)
			srv.revCheck = tt.check
			rec := httptest.NewRecorder()
			srv.handleRevocationCheck(rec, idRequest(http.MethodPost, tt.id))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.res.markRevokedN != tt.wantPersist {
				t.Fatalf("MarkRevokedViaCRL calls = %d, want %d", tt.res.markRevokedN, tt.wantPersist)
			}
		})
	}
}

func TestHandleRenewalKit_Statuses(t *testing.T) {
	t.Parallel()

	cn := "app.example.com"
	tests := []struct {
		name  string
		res   *fakeResourceStore
		id    string
		query string
		want  int
	}{
		{"invalid id", &fakeResourceStore{}, "nope", "?target=agent&role=web", http.StatusBadRequest},
		{"not found", &fakeResourceStore{certErr: store.ErrCertificateNotFound}, uuid.New().String(), "?target=agent&role=web", http.StatusNotFound},
		{"missing role", &fakeResourceStore{cert: store.Certificate{SubjectCN: &cn}}, uuid.New().String(), "?target=agent", http.StatusBadRequest},
		{"success agent", &fakeResourceStore{cert: store.Certificate{SubjectCN: &cn}}, uuid.New().String(), "?target=agent&role=web", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.id)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleRenewalKit(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusOK && !strings.Contains(rec.Body.String(), "vault-agent.hcl") {
				t.Fatalf("success body missing artifact: %s", rec.Body.String())
			}
		})
	}
}

// TestCertificateRoutes_Registered exercises the real Router so a dropped route
// (e.g. DELETE removed while adding catalog-import) fails loudly instead of only
// through direct handler calls.
func TestCertificateRoutes_Registered(t *testing.T) {
	t.Parallel()

	id := uuid.New().String()
	srv := newResourceServer(&fakeResourceStore{})

	cases := []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodPost, "/api/v1/certificates/" + id + "/catalog-import", `{"consent":true}`, http.StatusOK},
		{http.MethodGet, "/api/v1/certificates/" + id + "/choose", "", http.StatusOK},
		// default fake cert has no SubjectCN, so renewal-kit generation 400s — which
		// still proves the route is registered (not 404/405).
		{http.MethodGet, "/api/v1/certificates/" + id + "/renewal-kit?target=agent&role=web", "", http.StatusBadRequest},
		{http.MethodPost, "/api/v1/certificates/" + id + "/revocation-check", "", http.StatusOK},
		// renewer is nil on the resource-only server, so the route resolving to
		// 503 (not 404/405) proves it is registered.
		{http.MethodPost, "/api/v1/certificates/" + id + "/renew", `{"consent":true,"role":"web"}`, http.StatusServiceUnavailable},
		{http.MethodDelete, "/api/v1/certificates/" + id, "", http.StatusNoContent},
		{http.MethodDelete, "/api/v1/issuers/" + id, "", http.StatusNoContent},
		// importer is nil on the resource-only server, so the route resolving to
		// 503 (not 404/405) proves it is registered.
		{http.MethodPost, "/api/v1/issuers/" + id + "/import", `{"consent":true,"mount":"pki"}`, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		var body io.Reader
		if c.body != "" {
			body = strings.NewReader(c.body)
		}
		req := httptest.NewRequest(c.method, c.path, body)
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)
		if rec.Code == http.StatusMethodNotAllowed || rec.Code == http.StatusNotFound {
			t.Fatalf("%s %s: route not registered (got %d)", c.method, c.path, rec.Code)
		}
		if rec.Code != c.want {
			t.Fatalf("%s %s: status = %d, want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}
