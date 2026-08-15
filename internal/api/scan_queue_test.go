package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type alwaysFullScanCreator struct{}

func (alwaysFullScanCreator) CreateScan(context.Context, []string, []string, []int, int, int) (store.Scan, error) {
	return store.Scan{}, store.ErrScanQueueFull
}

func TestCreateScan_QueueFullReturns503(t *testing.T) {
	t.Parallel()
	srv := newAuthServer(config.Config{
		StaticTokens: map[string]string{roleScannerOperator: tokScanner},
	})
	srv.scans = alwaysFullScanCreator{}

	body := `{"consent":true,"cidrs":["203.0.113.1/32"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokScanner)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
}

func TestCreateScan_DoesNotBlockOnChannel(t *testing.T) {
	t.Parallel()
	// POST only persists; worker is nil / no Enqueue — must return 202 immediately.
	srv := newAuthServer(config.Config{
		StaticTokens: map[string]string{roleScannerOperator: tokScanner},
	})
	srv.scans = stubScanCreator{}
	srv.worker = nil

	body := `{"consent":true,"cidrs":["203.0.113.1/32"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokScanner)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}
}
