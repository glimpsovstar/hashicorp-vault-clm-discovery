package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeRenewer struct {
	gotVars map[string]any
	ref     RenewRef
	err     error
	calls   int
}

func (f *fakeRenewer) Renew(_ context.Context, extraVars map[string]any) (RenewRef, error) {
	f.calls++
	f.gotVars = extraVars
	if f.err != nil {
		return RenewRef{}, f.err
	}
	return f.ref, nil
}

func TestHandleRenewCertificate_Statuses(t *testing.T) {
	t.Parallel()

	cn := "app.example.com"
	withCN := func() *fakeResourceStore { return &fakeResourceStore{cert: store.Certificate{SubjectCN: &cn}} }

	tests := []struct {
		name         string
		res          *fakeResourceStore
		renewer      renewLauncher // nil => AAP not configured
		id           string
		body         string
		want         int
		wantLaunched bool
	}{
		{"invalid id", withCN(), &fakeRenewer{}, "nope", `{"consent":true,"role":"web"}`, http.StatusBadRequest, false},
		{"aap not configured", withCN(), nil, uuid.New().String(), `{"consent":true,"role":"web"}`, http.StatusServiceUnavailable, false},
		{"no consent", withCN(), &fakeRenewer{}, uuid.New().String(), `{"consent":false,"role":"web"}`, http.StatusBadRequest, false},
		{"bad json", withCN(), &fakeRenewer{}, uuid.New().String(), `{`, http.StatusBadRequest, false},
		{"not found", &fakeResourceStore{certErr: store.ErrCertificateNotFound}, &fakeRenewer{}, uuid.New().String(), `{"consent":true,"role":"web"}`, http.StatusNotFound, false},
		{"missing role", withCN(), &fakeRenewer{}, uuid.New().String(), `{"consent":true}`, http.StatusBadRequest, false},
		{"invalid role", withCN(), &fakeRenewer{}, uuid.New().String(), `{"consent":true,"role":"../evil"}`, http.StatusBadRequest, false},
		{"ssti ttl rejected", withCN(), &fakeRenewer{}, uuid.New().String(), `{"consent":true,"role":"web","ttl":"{{ lookup('pipe','id') }}"}`, http.StatusBadRequest, false},
		{"ssti alt_names rejected", withCN(), &fakeRenewer{}, uuid.New().String(), `{"consent":true,"role":"web","alt_names":"{{evil}}"}`, http.StatusBadRequest, false},
		{"launch failure", withCN(), &fakeRenewer{err: context.DeadlineExceeded}, uuid.New().String(), `{"consent":true,"role":"web"}`, http.StatusBadGateway, true},
		{"success", withCN(), &fakeRenewer{ref: RenewRef{JobID: 42}}, uuid.New().String(), `{"consent":true,"role":"web-server","service":"nginx"}`, http.StatusAccepted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newResourceServer(tt.res)
			srv.cfg.AAPDefaultMount = "pki"
			srv.renewer = tt.renewer // may be nil
			rec := httptest.NewRecorder()
			srv.handleRenewCertificate(rec, idRequestBody(http.MethodPost, tt.id, tt.body))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.want, rec.Body.String())
			}
			if fr, ok := tt.renewer.(*fakeRenewer); ok {
				launched := fr.calls > 0
				if launched != tt.wantLaunched {
					t.Fatalf("launched = %v, want %v", launched, tt.wantLaunched)
				}
				if tt.want == http.StatusAccepted {
					if fr.gotVars["cert_common_name_override"] != cn {
						t.Fatalf("extra_vars CN = %v, want %q", fr.gotVars["cert_common_name_override"], cn)
					}
					if fr.gotVars["vault_pki_role"] != "web-server" {
						t.Fatalf("extra_vars role = %v, want web-server", fr.gotVars["vault_pki_role"])
					}
					if fr.gotVars["cert_service_type"] != "nginx" {
						t.Fatalf("extra_vars service = %v, want nginx", fr.gotVars["cert_service_type"])
					}
					if fr.gotVars["vault_pki_mount"] != "pki" {
						t.Fatalf("extra_vars mount = %v, want default pki", fr.gotVars["vault_pki_mount"])
					}
					if !strings.Contains(rec.Body.String(), `"job_id":42`) {
						t.Fatalf("response missing job id: %s", rec.Body.String())
					}
					if !strings.Contains(rec.Body.String(), `"lifecycle_job_id"`) {
						t.Fatalf("response missing lifecycle_job_id: %s", rec.Body.String())
					}
					if fl, ok := srv.lifecycle.(*fakeLifecycleStore); ok {
						if !fl.gotPersist {
							t.Fatal("expected PersistRenewLaunch before 202")
						}
						if fl.gotRenewalCfg == nil || fl.gotRenewalCfg.Role != "web-server" {
							t.Fatalf("SetRenewalConfig via persist missing: %#v", fl.gotRenewalCfg)
						}
					}
				}
			}
		})
	}
}

func TestHandleRenewCertificate_ForwardsOptionalVars(t *testing.T) {
	t.Parallel()

	cn := "app.example.com"
	fr := &fakeRenewer{ref: RenewRef{JobID: 7, Workflow: true}}
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{SubjectCN: &cn}})
	srv.cfg.AAPDefaultMount = "pki"
	srv.renewer = fr

	body := `{"consent":true,"role":"web-server","service":"nginx","mount":"pki-int","target_hosts":"web_group","ttl":"72h","alt_names":"a.example.com b.example.com"}`
	rec := httptest.NewRecorder()
	srv.handleRenewCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), body))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}
	want := map[string]any{
		"cert_common_name_override": cn,
		"vault_pki_mount":           "pki-int",
		"vault_pki_role":            "web-server",
		"cert_service_type":         "nginx",
		"target_hosts":              "web_group",
		"vault_cert_ttl":            "72h",
		"cert_alt_names_override":   "a.example.com b.example.com",
	}
	for k, v := range want {
		if fr.gotVars[k] != v {
			t.Fatalf("extra_vars[%q] = %v, want %v", k, fr.gotVars[k], v)
		}
	}
	if !strings.Contains(rec.Body.String(), `"workflow":true`) {
		t.Fatalf("response should reflect workflow job: %s", rec.Body.String())
	}
}
