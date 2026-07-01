package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeComplianceStore struct {
	certs   []store.Certificate
	scan    store.Scan
	scanErr error
	listErr error
}

func (f *fakeComplianceStore) ListCertificates(_ context.Context, filter store.CertificateFilter) ([]store.Certificate, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	if filter.Offset >= len(f.certs) {
		return nil, len(f.certs), nil
	}
	end := filter.Offset + filter.Limit
	if end > len(f.certs) {
		end = len(f.certs)
	}
	return f.certs[filter.Offset:end], len(f.certs), nil
}

func (f *fakeComplianceStore) GetScan(_ context.Context, id uuid.UUID) (store.Scan, error) {
	if f.scanErr != nil {
		return store.Scan{}, f.scanErr
	}
	if f.scan.ID == uuid.Nil {
		f.scan.ID = id
	}
	return f.scan, nil
}

func TestHandleGetScanCompliance_Success(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.compliance = &fakeComplianceStore{
		scan: store.Scan{ID: scanID, Status: "completed"},
		certs: []store.Certificate{
			{
				ID:                 uuid.New(),
				FingerprintSHA256:  "fp-sc081",
				SubjectCN:          strPtr("long.example.com"),
				NotBefore:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
				KeyType:            "RSA",
				KeyBits:            2048,
				SignatureAlgorithm: "SHA256-RSA",
				CertScope:          governance.ScopeExternal,
				DaysUntilExpiry:    300,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/compliance", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanCompliance(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var summary compliance.ComplianceSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.ScanID != scanID {
		t.Fatalf("scan_id = %s, want %s", summary.ScanID, scanID)
	}
	if summary.SC081ViolationCount < 1 {
		t.Fatalf("sc081_violation_count = %d, want >= 1", summary.SC081ViolationCount)
	}
}

func TestHandleGetComplianceSummary_EstateWide(t *testing.T) {
	t.Parallel()

	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.compliance = &fakeComplianceStore{
		certs: []store.Certificate{
			{
				ID:                 uuid.New(),
				FingerprintSHA256:  "fp-weak",
				SubjectCN:          strPtr("weak.example.com"),
				NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
				KeyType:            "RSA",
				KeyBits:            1024,
				SignatureAlgorithm: "SHA1-RSA",
				CertScope:          governance.ScopeExternal,
				DaysUntilExpiry:    100,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/summary", nil)
	rec := httptest.NewRecorder()
	srv.handleGetComplianceSummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var summary compliance.ComplianceSummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.TotalCerts != 1 {
		t.Fatalf("total_certs = %d, want 1", summary.TotalCerts)
	}
	if summary.FindingsByPack["crypto"] < 1 {
		t.Fatalf("crypto findings = %d, want >= 1", summary.FindingsByPack["crypto"])
	}
}

func TestHandleGetScanCompliance_NotFound(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.compliance = &fakeComplianceStore{scanErr: store.ErrScanNotFound}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/compliance", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanCompliance(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestHandleGetScanCompliance_DBError(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	// A DB/IO failure (not ErrScanNotFound) must surface as 500, not be masked
	// as a 404 "scan not found".
	srv.compliance = &fakeComplianceStore{scanErr: context.Canceled}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scanID.String()+"/compliance", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	srv.handleGetScanCompliance(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestHandleGetComplianceSummary_RouteRegistered(t *testing.T) {
	t.Parallel()

	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.compliance = &fakeComplianceStore{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/summary", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
