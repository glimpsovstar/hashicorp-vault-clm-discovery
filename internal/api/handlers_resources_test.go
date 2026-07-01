package api

import (
	"context"
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

type fakeResourceStore struct {
	scan            store.Scan
	scanErr         error
	cert            store.Certificate
	certErr         error
	certs           []store.Certificate
	listErr         error
	deleteScanErr   error
	deleteCertErr   error
	deleteIssuerErr error
}

func (f *fakeResourceStore) GetCertificate(_ context.Context, _ uuid.UUID) (store.Certificate, error) {
	if f.certErr != nil {
		return store.Certificate{}, f.certErr
	}
	return f.cert, nil
}

func (f *fakeResourceStore) GetScan(_ context.Context, id uuid.UUID) (store.Scan, error) {
	if f.scanErr != nil {
		return store.Scan{}, f.scanErr
	}
	if f.scan.ID == uuid.Nil {
		f.scan.ID = id
	}
	return f.scan, nil
}

func (f *fakeResourceStore) ListCertificates(_ context.Context, filter store.CertificateFilter) ([]store.Certificate, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.certs, len(f.certs), nil
}

func (f *fakeResourceStore) DeleteScan(context.Context, uuid.UUID) error { return f.deleteScanErr }
func (f *fakeResourceStore) DeleteCertificate(context.Context, uuid.UUID) error {
	return f.deleteCertErr
}
func (f *fakeResourceStore) DeleteIssuer(context.Context, uuid.UUID) error { return f.deleteIssuerErr }

func newResourceServer(res resourceStore) *Server {
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.resources = res
	return srv
}

// idRequest builds a request carrying an "id" chi URL param.
func idRequest(method, id string) *http.Request {
	req := httptest.NewRequest(method, "/", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestHandleGetScan_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		id   string
		want int
	}{
		{name: "invalid id", res: &fakeResourceStore{}, id: "not-a-uuid", want: http.StatusBadRequest},
		{name: "not found", res: &fakeResourceStore{scanErr: store.ErrScanNotFound}, id: uuid.New().String(), want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{scanErr: context.Canceled}, id: uuid.New().String(), want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{scan: store.Scan{Status: "completed"}}, id: uuid.New().String(), want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetScan(rec, idRequest(http.MethodGet, tt.id))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleListScanCertificates_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "scan not found", res: &fakeResourceStore{scanErr: store.ErrScanNotFound}, want: http.StatusNotFound},
		{name: "scan db error", res: &fakeResourceStore{scanErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "list db error", res: &fakeResourceStore{listErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleListScanCertificates(rec, idRequest(http.MethodGet, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleGetCertificatePEM_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{certErr: store.ErrCertificateNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{certErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{cert: store.Certificate{PEM: "-----BEGIN CERTIFICATE-----"}}, want: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetCertificatePEM(rec, idRequest(http.MethodGet, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// handleGetCertificate's success path also reads observations from the concrete
// store, so only the lookup error paths are unit-testable via the seam.
func TestHandleGetCertificate_ErrorStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{certErr: store.ErrCertificateNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{certErr: context.Canceled}, want: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleGetCertificate(rec, idRequest(http.MethodGet, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleDeleteScan_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{deleteScanErr: store.ErrScanNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{deleteScanErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleDeleteScan(rec, idRequest(http.MethodDelete, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleDeleteCertificate_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{deleteCertErr: store.ErrCertificateNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{deleteCertErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleDeleteCertificate(rec, idRequest(http.MethodDelete, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleDeleteIssuer_Statuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		res  *fakeResourceStore
		want int
	}{
		{name: "not found", res: &fakeResourceStore{deleteIssuerErr: store.ErrIssuerNotFound}, want: http.StatusNotFound},
		{name: "db error", res: &fakeResourceStore{deleteIssuerErr: context.Canceled}, want: http.StatusInternalServerError},
		{name: "success", res: &fakeResourceStore{}, want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			newResourceServer(tt.res).handleDeleteIssuer(rec, idRequest(http.MethodDelete, uuid.New().String()))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
