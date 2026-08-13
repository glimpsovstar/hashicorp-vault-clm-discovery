package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/revocation"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

func (a *recordingAuditor) allows() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, 0, len(a.events))
	for _, ev := range a.events {
		if ev.Decision == "allow" {
			out = append(out, ev)
		}
	}
	return out
}

func TestNewServerWiresStoreAuditor(t *testing.T) {
	t.Parallel()

	st := &store.Store{}
	srv := NewServer(config.Config{}, st, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if srv.auditor == nil {
		t.Fatal("NewServer must wire auditor when store is non-nil")
	}

	nilStore := NewServer(config.Config{}, nil, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if nilStore.auditor != nil {
		t.Fatal("NewServer must leave auditor nil when store is nil")
	}
}

func TestImportCASuccessWritesAuditWithActor(t *testing.T) {
	t.Parallel()

	srv, aud := newRBACServer(t)
	ca := store.Issuer{IsCA: true, PEM: "-----BEGIN CERTIFICATE-----\nSECRETPEM\n-----END CERTIFICATE-----"}
	srv.resources = &fakeResourceStore{issuer: ca}
	srv.importer = &fakeImporter{result: vault.IssuerImportResult{ImportedIssuers: []string{"iss-1"}}}

	id := uuid.New().String()
	rec := doRBAC(srv, http.MethodPost, "/api/v1/issuers/"+id+"/import", tokVaultImport, `{"consent":true,"mount":"pki"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("CA import status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	allows := aud.allows()
	if len(allows) == 0 {
		t.Fatal("successful CA import must append an audit allow with actor")
	}
	ev := allows[0]
	if ev.ActorID != "static:vault_import_admin" {
		t.Fatalf("ActorID = %q, want static:vault_import_admin", ev.ActorID)
	}
	if ev.ActorType != "user" {
		t.Fatalf("ActorType = %q, want user", ev.ActorType)
	}
	if ev.Role != roleVaultImportAdmin {
		t.Fatalf("Role = %q, want %s", ev.Role, roleVaultImportAdmin)
	}
	if ev.Decision != "allow" {
		t.Fatalf("Decision = %q, want allow", ev.Decision)
	}
	if ev.TargetType != "issuer" || ev.TargetID != id {
		t.Fatalf("target = %s/%s, want issuer/%s", ev.TargetType, ev.TargetID, id)
	}
	payload, _ := json.Marshal(ev.Payload)
	if strings.Contains(string(payload), "SECRETPEM") || strings.Contains(string(payload), "BEGIN CERTIFICATE") {
		t.Fatalf("audit payload leaked PEM: %s", payload)
	}
	if strings.Contains(string(payload), tokVaultImport) || strings.Contains(strings.ToLower(string(payload)), "authorization") {
		t.Fatalf("audit payload leaked token/Authorization: %s", payload)
	}
}

func TestPrivilegedMutationsWriteAuditAllow(t *testing.T) {
	t.Parallel()

	certID := uuid.New().String()
	scanID := uuid.New().String()
	issuerID := uuid.New().String()
	cn := "app.example.com"

	tests := []struct {
		name       string
		setup      func(*Server)
		method     string
		path       string
		token      string
		body       string
		wantStatus int
		wantAction string
	}{
		{
			name: "create scan",
			setup: func(s *Server) {
				s.scans = stubScanCreator{}
			},
			method:     http.MethodPost,
			path:       "/api/v1/scans",
			token:      tokScanner,
			body:       `{"consent":true,"cidrs":["10.0.0.0/24"]}`,
			wantStatus: http.StatusAccepted,
			wantAction: "create_scan",
		},
		{
			name: "catalog import",
			setup: func(s *Server) {
				s.resources = &fakeResourceStore{setStatusResult: store.Certificate{ManagedStatus: "imported"}}
			},
			method:     http.MethodPost,
			path:       "/api/v1/certificates/" + certID + "/catalog-import",
			token:      tokRemediator,
			body:       `{"consent":true}`,
			wantStatus: http.StatusOK,
			wantAction: "catalog_import",
		},
		{
			name: "renew",
			setup: func(s *Server) {
				s.resources = &fakeResourceStore{cert: store.Certificate{SubjectCN: &cn}}
				s.cfg.AAPDefaultMount = "pki"
				s.renewer = &fakeRenewer{ref: RenewRef{JobID: 7}}
			},
			method:     http.MethodPost,
			path:       "/api/v1/certificates/" + certID + "/renew",
			token:      tokRemediator,
			body:       `{"consent":true,"role":"web"}`,
			wantStatus: http.StatusAccepted,
			wantAction: "renew",
		},
		{
			name: "reconcile",
			setup: func(s *Server) {
				s.cfg.VaultAddr = "http://vault.example:8200"
				s.reconciler = &stubReconciler{summary: vault.Summary{Status: vault.StatusOK}}
			},
			method:     http.MethodPost,
			path:       "/api/v1/reconcile",
			token:      tokVaultImport,
			body:       `{}`,
			wantStatus: http.StatusOK,
			wantAction: "reconcile",
		},
		{
			name: "revocation check",
			setup: func(s *Server) {
				s.resources = &fakeResourceStore{cert: store.Certificate{SerialNumber: "01"}}
				s.revCheck = func(context.Context, revocation.CheckInput) (revocation.Result, error) {
					return revocation.Result{Status: revocation.StatusGood, Source: "ocsp"}, nil
				}
			},
			method:     http.MethodPost,
			path:       "/api/v1/certificates/" + certID + "/revocation-check",
			token:      tokRemediator,
			body:       `{}`,
			wantStatus: http.StatusOK,
			wantAction: "revoke",
		},
		{
			name:       "delete scan",
			setup:      func(s *Server) {},
			method:     http.MethodDelete,
			path:       "/api/v1/scans/" + scanID,
			token:      tokPlatform,
			wantStatus: http.StatusNoContent,
			wantAction: "delete",
		},
		{
			name:       "delete certificate",
			setup:      func(s *Server) {},
			method:     http.MethodDelete,
			path:       "/api/v1/certificates/" + certID,
			token:      tokPlatform,
			wantStatus: http.StatusNoContent,
			wantAction: "delete",
		},
		{
			name:       "delete issuer",
			setup:      func(s *Server) {},
			method:     http.MethodDelete,
			path:       "/api/v1/issuers/" + issuerID,
			token:      tokPlatform,
			wantStatus: http.StatusNoContent,
			wantAction: "delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, aud := newRBACServer(t)
			tt.setup(srv)
			rec := doRBAC(srv, tt.method, tt.path, tt.token, tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			allows := aud.allows()
			if len(allows) == 0 {
				t.Fatalf("%s must append an audit allow", tt.name)
			}
			ev := allows[0]
			if ev.ActorID == "" || ev.ActorType != "user" {
				t.Fatalf("actor = %s/%s, want static:<role>/user", ev.ActorID, ev.ActorType)
			}
			if ev.Decision != "allow" {
				t.Fatalf("Decision = %q, want allow", ev.Decision)
			}
			if ev.Action != tt.wantAction {
				t.Fatalf("Action = %q, want %q", ev.Action, tt.wantAction)
			}
		})
	}
}

func TestAuditDenyUsesStaticActorID(t *testing.T) {
	t.Parallel()

	srv, aud := newRBACServer(t)
	rec := doRBAC(srv, http.MethodPost, "/api/v1/scans", tokViewer, `{"consent":true,"cidrs":["10.0.0.0/24"]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	denies := aud.denies()
	if len(denies) == 0 {
		t.Fatal("expected deny audit")
	}
	ev := denies[0]
	if ev.ActorID != "static:viewer" {
		t.Fatalf("ActorID = %q, want static:viewer", ev.ActorID)
	}
	if ev.ActorType != "user" {
		t.Fatalf("ActorType = %q, want user", ev.ActorType)
	}
}
