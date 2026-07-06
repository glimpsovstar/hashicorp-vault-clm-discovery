package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func renewableCert(cn, role string) store.Certificate {
	c := cn
	return store.Certificate{
		ID:            uuid.New(),
		SubjectCN:     &c,
		RenewalConfig: &store.RenewalConfig{Role: role, Mount: "pki-int", Service: "nginx"},
	}
}

func renewableCertWithTTL(cn, role, ttl string) store.Certificate {
	c := renewableCert(cn, role)
	c.RenewalConfig.TTL = ttl
	return c
}

func TestHandleRenewExpiring(t *testing.T) {
	t.Parallel()

	valid := renewableCert("app.example.com", "web-server")
	badCfg := renewableCert("bad.example.com", "../evil") // invalid role -> not launched

	tests := []struct {
		name         string
		renewer      renewLauncher // nil => AAP not configured
		res          *fakeResourceStore
		body         string
		want         int
		wantLaunched int
		wantFailed   int
	}{
		{"not configured", nil, &fakeResourceStore{}, `{"consent":true}`, http.StatusServiceUnavailable, 0, 0},
		{"no consent", &fakeRenewer{}, &fakeResourceStore{}, `{"consent":false}`, http.StatusBadRequest, 0, 0},
		{"bad json", &fakeRenewer{}, &fakeResourceStore{}, `{`, http.StatusBadRequest, 0, 0},
		{"list error", &fakeRenewer{}, &fakeResourceStore{renewableErr: context.Canceled}, `{"consent":true}`, http.StatusInternalServerError, 0, 0},
		{"empty eligible", &fakeRenewer{}, &fakeResourceStore{}, `{"consent":true}`, http.StatusAccepted, 0, 0},
		{"launches eligible", &fakeRenewer{ref: RenewRef{JobID: 1}}, &fakeResourceStore{renewable: []store.Certificate{valid}}, `{"consent":true,"within_days":30}`, http.StatusAccepted, 1, 0},
		{"invalid config captured", &fakeRenewer{ref: RenewRef{JobID: 1}}, &fakeResourceStore{renewable: []store.Certificate{badCfg}}, `{"consent":true}`, http.StatusAccepted, 0, 1},
		{"ssti ttl captured", &fakeRenewer{ref: RenewRef{JobID: 1}}, &fakeResourceStore{renewable: []store.Certificate{renewableCertWithTTL("x.example.com", "web", "{{ lookup('pipe','id') }}")}}, `{"consent":true}`, http.StatusAccepted, 0, 1},
		{"launch failure captured", &fakeRenewer{err: context.DeadlineExceeded}, &fakeResourceStore{renewable: []store.Certificate{valid}}, `{"consent":true}`, http.StatusAccepted, 0, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := newResourceServer(tt.res)
			srv.cfg.AAPDefaultMount = "pki"
			srv.cfg.ExpiringSoonDays = 30
			srv.renewer = tt.renewer

			req := httptest.NewRequest(http.MethodPost, "/renew-expiring", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			srv.handleRenewExpiring(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusAccepted {
				var resp struct {
					WithinDays int              `json:"within_days"`
					Eligible   int              `json:"eligible"`
					Launched   []map[string]any `json:"launched"`
					Failed     []map[string]any `json:"failed"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if len(resp.Launched) != tt.wantLaunched {
					t.Fatalf("launched = %d, want %d (%s)", len(resp.Launched), tt.wantLaunched, rec.Body.String())
				}
				if len(resp.Failed) != tt.wantFailed {
					t.Fatalf("failed = %d, want %d (%s)", len(resp.Failed), tt.wantFailed, rec.Body.String())
				}
			}
		})
	}
}

func TestHandleRenewExpiring_DefaultsWindow(t *testing.T) {
	t.Parallel()

	fr := &fakeRenewer{ref: RenewRef{JobID: 5}}
	srv := newResourceServer(&fakeResourceStore{renewable: []store.Certificate{renewableCert("a.example.com", "web")}})
	srv.cfg.AAPDefaultMount = "pki"
	srv.cfg.ExpiringSoonDays = 45
	srv.renewer = fr

	req := httptest.NewRequest(http.MethodPost, "/renew-expiring", strings.NewReader(`{"consent":true}`))
	rec := httptest.NewRecorder()
	srv.handleRenewExpiring(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"within_days":45`) {
		t.Fatalf("expected within_days to default to EXPIRING_SOON_DAYS (45): %s", rec.Body.String())
	}
}
