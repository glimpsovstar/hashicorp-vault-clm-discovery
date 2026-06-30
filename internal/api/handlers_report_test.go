package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeReportStore struct {
	scan    store.Scan
	scanErr error
	managed int
	disc    int
	certs   []store.Certificate
}

func (f *fakeReportStore) GetScan(_ context.Context, id uuid.UUID) (store.Scan, error) {
	if f.scanErr != nil {
		return store.Scan{}, f.scanErr
	}
	if f.scan.ID == uuid.Nil {
		f.scan.ID = id
	}
	return f.scan, nil
}

func (f *fakeReportStore) CountByManagedStatus(_ context.Context, _ *uuid.UUID) (int, int, error) {
	return f.managed, f.disc, nil
}

func (f *fakeReportStore) ListCertificates(_ context.Context, filter store.CertificateFilter) ([]store.Certificate, int, error) {
	if filter.Offset >= len(f.certs) {
		return nil, len(f.certs), nil
	}
	end := filter.Offset + filter.Limit
	if end > len(f.certs) {
		end = len(f.certs)
	}
	return f.certs[filter.Offset:end], len(f.certs), nil
}

func TestHandleGetScanReport_MarkdownCompleted(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	finished := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.report = &fakeReportStore{
		scan: store.Scan{
			ID:               scanID,
			Status:           "completed",
			Hostnames:        []string{"demo.example.com"},
			TargetsTotal:     1,
			TargetsSucceeded: 1,
			CertsFound:       2,
			FinishedAt:       &finished,
		},
		managed: 1,
		disc:    2,
		certs: []store.Certificate{
			{
				ID:                uuid.New(),
				FingerprintSHA256: "fp1",
				SubjectCN:         strPtr("demo.example.com"),
				NotBefore:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:          time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
				KeyType:           "RSA",
				KeyBits:           2048,
				CertScope:         governance.ScopeExternal,
				DaysUntilExpiry:   100,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/report", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanReport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/markdown") {
		t.Fatalf("content-type = %q, want text/markdown", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# Executive summary") {
		t.Fatalf("body missing executive summary: %s", body)
	}
}

func TestHandleGetScanReport_NotCompleted(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.report = &fakeReportStore{
		scan: store.Scan{ID: scanID, Status: "running"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/report", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanReport(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleGetScanReport_StoreErrorReturns500(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.report = &fakeReportStore{scanErr: errors.New("connection refused")}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/report", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanReport(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (a DB error must not be masked as 404)", rec.Code)
	}
}

func TestHandleGetScanReport_JSONFormat(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.report = &fakeReportStore{
		scan:    store.Scan{ID: scanID, Status: "completed"},
		managed: 0,
		disc:    1,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/report?format=json", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanReport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), `"report_version"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestHandleGetScanReport_RouteRegistered(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.report = &fakeReportStore{
		scan: store.Scan{ID: scanID, Status: "completed"},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/report", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
