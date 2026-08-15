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

type fakeRevoker struct {
	gotVars map[string]any
	ref     RenewRef
	err     error
	calls   int
}

func (f *fakeRevoker) Revoke(_ context.Context, extraVars map[string]any) (RenewRef, error) {
	f.calls++
	f.gotVars = extraVars
	if f.err != nil {
		return RenewRef{}, f.err
	}
	return f.ref, nil
}

func TestHandleRevokeCertificate_Statuses(t *testing.T) {
	t.Parallel()

	cn := "app.example.com"
	cert := store.Certificate{
		SubjectCN:         &cn,
		SerialNumber:      "abc123",
		FingerprintSHA256: "fpdeadbeef",
	}
	withCert := func() *fakeResourceStore { return &fakeResourceStore{cert: cert} }

	tests := []struct {
		name         string
		res          *fakeResourceStore
		revoker      revokeLauncher
		id           string
		body         string
		want         int
		wantLaunched bool
	}{
		{"invalid id", withCert(), &fakeRevoker{}, "nope", `{"consent":true,"reason":"compromised"}`, http.StatusBadRequest, false},
		{"aap not configured", withCert(), nil, uuid.New().String(), `{"consent":true,"reason":"compromised"}`, http.StatusServiceUnavailable, false},
		{"no consent", withCert(), &fakeRevoker{}, uuid.New().String(), `{"consent":false,"reason":"compromised"}`, http.StatusBadRequest, false},
		{"bad json", withCert(), &fakeRevoker{}, uuid.New().String(), `{`, http.StatusBadRequest, false},
		{"not found", &fakeResourceStore{certErr: store.ErrCertificateNotFound}, &fakeRevoker{}, uuid.New().String(), `{"consent":true,"reason":"compromised"}`, http.StatusNotFound, false},
		{"missing reason", withCert(), &fakeRevoker{}, uuid.New().String(), `{"consent":true}`, http.StatusBadRequest, false},
		{"ssti reason rejected", withCert(), &fakeRevoker{}, uuid.New().String(), `{"consent":true,"reason":"{{ lookup('pipe','id') }}"}`, http.StatusBadRequest, false},
		{"invalid mount", withCert(), &fakeRevoker{}, uuid.New().String(), `{"consent":true,"reason":"compromised","mount":"../sys"}`, http.StatusBadRequest, false},
		{"launch failure", withCert(), &fakeRevoker{err: context.DeadlineExceeded}, uuid.New().String(), `{"consent":true,"reason":"compromised"}`, http.StatusBadGateway, true},
		{"success", withCert(), &fakeRevoker{ref: RenewRef{JobID: 99}}, uuid.New().String(), `{"consent":true,"reason":"key-compromise","mount":"pki-int"}`, http.StatusAccepted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newResourceServer(tt.res)
			srv.cfg.AAPDefaultMount = "pki"
			srv.revoker = tt.revoker
			rec := httptest.NewRecorder()
			srv.handleRevokeCertificate(rec, idRequestBody(http.MethodPost, tt.id, tt.body))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.want, rec.Body.String())
			}
			if fr, ok := tt.revoker.(*fakeRevoker); ok {
				launched := fr.calls > 0
				if launched != tt.wantLaunched {
					t.Fatalf("launched = %v, want %v", launched, tt.wantLaunched)
				}
				if tt.want == http.StatusAccepted {
					if fr.gotVars["clm_action"] != "clm_revoke" {
						t.Fatalf("clm_action = %v, want clm_revoke", fr.gotVars["clm_action"])
					}
					if fr.gotVars["serial_number"] != "abc123" {
						t.Fatalf("serial = %v, want abc123", fr.gotVars["serial_number"])
					}
					if fr.gotVars["vault_pki_mount"] != "pki-int" {
						t.Fatalf("mount = %v, want pki-int", fr.gotVars["vault_pki_mount"])
					}
					if fr.gotVars["reason"] != "key-compromise" {
						t.Fatalf("reason = %v, want key-compromise", fr.gotVars["reason"])
					}
					if fr.gotVars["fingerprint_sha256"] != "fpdeadbeef" {
						t.Fatalf("fingerprint = %v", fr.gotVars["fingerprint_sha256"])
					}
					if _, ok := fr.gotVars["certificate_id"]; !ok {
						t.Fatal("missing certificate_id")
					}
					for _, secretKey := range []string{"token", "password", "secret", "vault_token", "aap_token"} {
						if _, ok := fr.gotVars[secretKey]; ok {
							t.Fatalf("extra_vars must not contain %q", secretKey)
						}
					}
					if !strings.Contains(rec.Body.String(), `"job_id":99`) {
						t.Fatalf("response missing job id: %s", rec.Body.String())
					}
				}
			}
		})
	}
}

func TestHandleRevokeCertificate_DoesNotCallVaultRevoke(t *testing.T) {
	t.Parallel()

	// Guard: revoke path must not import or depend on a Vault revoke API.
	// Presence of the revokeLauncher seam + nil vault importer proves CLM
	// launches AAP only. This test documents the invariant for reviewers.
	cn := "app.example.com"
	fr := &fakeRevoker{ref: RenewRef{JobID: 1}}
	srv := newResourceServer(&fakeResourceStore{cert: store.Certificate{
		SubjectCN: &cn, SerialNumber: "1", FingerprintSHA256: "fp",
	}})
	srv.cfg.AAPDefaultMount = "pki"
	srv.revoker = fr
	srv.importer = nil // Vault write identity unused for revoke

	rec := httptest.NewRecorder()
	srv.handleRevokeCertificate(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"reason":"superseded"}`))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}
	if fr.calls != 1 {
		t.Fatalf("revoker calls = %d, want 1", fr.calls)
	}
}

func TestRevokeExtraVars_Contract(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	vars := revokeExtraVars(id, "deadbeef", "fp", "pki", "compromised")
	want := map[string]any{
		"clm_action":         "clm_revoke",
		"serial_number":      "deadbeef",
		"fingerprint_sha256": "fp",
		"vault_pki_mount":    "pki",
		"certificate_id":     id.String(),
		"reason":             "compromised",
	}
	for k, v := range want {
		if vars[k] != v {
			t.Fatalf("extra_vars[%q] = %v, want %v", k, vars[k], v)
		}
	}
	if len(vars) != len(want) {
		t.Fatalf("extra_vars has unexpected keys: %#v", vars)
	}
}
