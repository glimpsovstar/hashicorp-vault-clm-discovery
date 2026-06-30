package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

type stubReconciler struct {
	summary vault.Summary
	err     error
	called  bool
}

func (s *stubReconciler) Reconcile(context.Context) (vault.Summary, error) {
	s.called = true
	return s.summary, s.err
}

func TestHandleReconcile_VaultNotConfigured(t *testing.T) {
	t.Parallel()

	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reconcile", nil)
	rec := httptest.NewRecorder()
	srv.handleReconcile(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "vault not configured" {
		t.Fatalf("error = %q", body["error"])
	}
}

func TestHandleReconcile_Success(t *testing.T) {
	t.Parallel()

	stub := &stubReconciler{
		summary: vault.Summary{
			MountsScanned:  2,
			VaultCertsRead: 15,
			Matched:        12,
			UnmatchedCLM:   35,
			Errors:         []string{},
		},
	}
	srv := NewServer(config.Config{VaultAddr: "http://vault.example:8200"}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.reconciler = stub

	req := httptest.NewRequest(http.MethodPost, "/api/v1/reconcile", nil)
	rec := httptest.NewRecorder()
	srv.handleReconcile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !stub.called {
		t.Fatal("expected reconciler to be called")
	}

	var summary vault.Summary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Matched != 12 {
		t.Fatalf("matched = %d, want 12", summary.Matched)
	}
	if summary.UnmatchedCLM != 35 {
		t.Fatalf("unmatched_clm = %d, want 35", summary.UnmatchedCLM)
	}
}

func TestHandleReconcile_RouteRegistered(t *testing.T) {
	t.Parallel()

	stub := &stubReconciler{summary: vault.Summary{Errors: []string{}}}
	srv := NewServer(config.Config{VaultAddr: "http://vault.example:8200"}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.reconciler = stub

	req := httptest.NewRequest(http.MethodPost, "/api/v1/reconcile", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
