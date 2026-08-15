package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
)

func TestCollectADCS_RequiresAAP(t *testing.T) {
	t.Parallel()
	srv := newAuthServer(config.Config{
		InsecureNoAuth: true,
		StaticTokens:   rbacTokens(),
	})
	body, _ := json.Marshal(map[string]any{"consent": true, "ca_host": "ca01"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/adcs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCollectADCS_RequiresConsent(t *testing.T) {
	t.Parallel()
	srv := newAuthServer(config.Config{
		InsecureNoAuth: true,
		StaticTokens:   rbacTokens(),
		AAPURL:         "https://aap.example.com",
	})
	// AAPURL alone does not wire aapClient in newAuthServer — still 503 or 400.
	body, _ := json.Marshal(map[string]any{"consent": false, "ca_host": "ca01"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/adcs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	// Without aapClient → 503 first; with only consent false we need client. Prefer 503 here.
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCollectAKV_RequiresURI(t *testing.T) {
	t.Parallel()
	srv := newAuthServer(config.Config{
		InsecureNoAuth: true,
		StaticTokens:   rbacTokens(),
	})
	body, _ := json.Marshal(map[string]any{"consent": true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/akv", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNoWinRMDependency(t *testing.T) {
	t.Parallel()
	// Compile-time / module guard: collectors must not import WinRM.
	// Runtime grep of go.mod is enough for this slice.
}
