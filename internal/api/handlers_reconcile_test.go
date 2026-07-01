package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

type stubReconciler struct {
	summary     vault.Summary
	err         error
	called      bool
	hadDeadline bool
}

func (s *stubReconciler) Reconcile(ctx context.Context) (vault.Summary, error) {
	s.called = true
	_, s.hadDeadline = ctx.Deadline()
	return s.summary, s.err
}

func TestMaybeReconcileAfterScan_LogsFailureNotComplete(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Every mount failed: Reconcile returns status=failed with a nil error. The
	// background path must not log this as a completed reconcile.
	stub := &stubReconciler{summary: vault.Summary{Status: vault.StatusFailed, Errors: []string{"pki/: 403"}}}
	srv := NewServer(config.Config{VaultAddr: "http://vault.example:8200", ReconcileOnScanComplete: true}, &store.Store{}, scanner.New(scanner.Config{}), logger)
	srv.reconciler = stub

	srv.maybeReconcileAfterScan(context.Background(), uuid.New())

	logs := buf.String()
	if strings.Contains(logs, "reconcile after scan complete") {
		t.Fatalf("failed reconcile must not log 'complete':\n%s", logs)
	}
	if !strings.Contains(logs, "status=failed") {
		t.Fatalf("log should record status=failed:\n%s", logs)
	}
	if !strings.Contains(logs, "level=WARN") {
		t.Fatalf("failed reconcile should log at WARN:\n%s", logs)
	}
}

func TestMaybeReconcileAfterScan_BoundsContext(t *testing.T) {
	t.Parallel()

	stub := &stubReconciler{summary: vault.Summary{Status: vault.StatusOK}}
	srv := NewServer(config.Config{VaultAddr: "http://vault.example:8200", ReconcileOnScanComplete: true}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.reconciler = stub

	// A background context has no deadline; the post-scan reconcile must add one
	// so a hung Vault cannot wedge the single scan worker.
	srv.maybeReconcileAfterScan(context.Background(), uuid.New())

	if !stub.called {
		t.Fatal("expected reconcile to be called")
	}
	if !stub.hadDeadline {
		t.Fatal("expected the post-scan reconcile context to carry a deadline")
	}
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
			Status:         vault.StatusOK,
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
	if summary.Status != vault.StatusOK {
		t.Fatalf("status = %q, want ok", summary.Status)
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
