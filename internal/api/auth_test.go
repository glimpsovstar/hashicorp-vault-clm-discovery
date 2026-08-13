package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func newAuthServer(cfg config.Config) *Server {
	return NewServer(cfg, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// openTestConfig enables the UAT hatch so Router() tests that are not about
// authentication keep working under default-deny.
func openTestConfig(cfg config.Config) config.Config {
	cfg.InsecureNoAuth = true
	return cfg
}

func TestAuth_UnauthenticatedCertificates401(t *testing.T) {
	t.Parallel()

	srv := newAuthServer(config.Config{
		AuthMode:     "static_token",
		StaticTokens: map[string]string{"viewer": "tok_v"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestAuth_HealthAllowsNoToken(t *testing.T) {
	t.Parallel()

	srv := newAuthServer(config.Config{
		AuthMode:     "static_token",
		StaticTokens: map[string]string{"viewer": "tok_v"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("health must not require auth, got 401 (body: %s)", rec.Body.String())
	}
}

func TestAuth_InvalidToken401(t *testing.T) {
	t.Parallel()

	srv := newAuthServer(config.Config{
		StaticTokens: map[string]string{"viewer": "tok_v"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer tok_unknown")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestAuth_ValidStaticTokenNot401(t *testing.T) {
	t.Parallel()

	srv := newAuthServer(config.Config{
		StaticTokens: map[string]string{"viewer": "tok_v"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer tok_v")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("valid static token must not 401 (body: %s)", rec.Body.String())
	}
}

func TestAuth_HashedStaticTokenNot401(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256([]byte("s3cret"))
	srv := newAuthServer(config.Config{
		StaticTokens: map[string]string{"viewer": "sha256:" + hex.EncodeToString(sum[:])},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("valid hashed token must not 401 (body: %s)", rec.Body.String())
	}
}

func TestAuth_InsecureNoAuthAllowsWithoutToken(t *testing.T) {
	t.Parallel()

	srv := newAuthServer(config.Config{InsecureNoAuth: true})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("InsecureNoAuth must skip auth, got 401 (body: %s)", rec.Body.String())
	}
}

func TestAuth_StaticTokenSetsSettingsActor(t *testing.T) {
	t.Parallel()

	srv := newAuthServer(config.Config{
		VaultAddr:    "https://vault.example:8200",
		StaticTokens: map[string]string{"remediator": "tok_r", "viewer": "tok_v"},
	})
	srv.connections = newFakeConnections()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/connections", nil)
	req.Header.Set("Authorization", "Bearer tok_r")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remediator GET status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/connections", nil)
	req.Header.Set("Authorization", "Bearer tok_v")
	rec = httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}
