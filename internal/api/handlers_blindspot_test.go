package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeBlindSpotStore struct {
	managed, discovered int
	scan                store.Scan
	scanErr             error
	countErr            error
}

func (f *fakeBlindSpotStore) CountByManagedStatus(_ context.Context, scanID *uuid.UUID) (int, int, error) {
	if f.countErr != nil {
		return 0, 0, f.countErr
	}
	return f.managed, f.discovered, nil
}

func (f *fakeBlindSpotStore) GetScan(_ context.Context, id uuid.UUID) (store.Scan, error) {
	if f.scanErr != nil {
		return store.Scan{}, f.scanErr
	}
	if f.scan.ID == uuid.Nil {
		f.scan.ID = id
	}
	return f.scan, nil
}

func TestBuildBlindSpotSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		managed    int
		discovered int
		wantShadow int
	}{
		{name: "shadow certs", managed: 12, discovered: 47, wantShadow: 35},
		{name: "all managed", managed: 10, discovered: 10, wantShadow: 0},
		{name: "none managed", managed: 0, discovered: 5, wantShadow: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildBlindSpotSummary(tt.managed, tt.discovered)
			if got.VaultManaged != tt.managed {
				t.Fatalf("vault_managed = %d, want %d", got.VaultManaged, tt.managed)
			}
			if got.Discovered != tt.discovered {
				t.Fatalf("discovered = %d, want %d", got.Discovered, tt.discovered)
			}
			if got.Shadow != tt.wantShadow {
				t.Fatalf("shadow = %d, want %d", got.Shadow, tt.wantShadow)
			}
			if got.SC081Violations != 0 {
				t.Fatalf("sc081_violations = %d, want 0", got.SC081Violations)
			}
		})
	}
}

func TestHandleGetBlindSpot_EstateWide(t *testing.T) {
	t.Parallel()

	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.blindSpot = &fakeBlindSpotStore{managed: 12, discovered: 47}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/blindspot", nil)
	rec := httptest.NewRecorder()
	srv.handleGetBlindSpot(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var summary BlindSpotSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.VaultManaged != 12 || summary.Discovered != 47 || summary.Shadow != 35 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestHandleGetScanBlindSpot_Success(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.blindSpot = &fakeBlindSpotStore{
		managed:    3,
		discovered: 8,
		scan:       store.Scan{ID: scanID, Status: "completed"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/blindspot", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanBlindSpot(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var summary BlindSpotSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Shadow != 5 {
		t.Fatalf("shadow = %d, want 5", summary.Shadow)
	}
}

func TestHandleGetScanBlindSpot_NotFound(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.blindSpot = &fakeBlindSpotStore{scanErr: errors.New("scan not found")}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/blindspot", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanBlindSpot(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleGetBlindSpot_RouteRegistered(t *testing.T) {
	t.Parallel()

	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.blindSpot = &fakeBlindSpotStore{managed: 1, discovered: 4}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/blindspot", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
