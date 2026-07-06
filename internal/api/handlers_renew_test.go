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
				}
			}
		})
	}
}
