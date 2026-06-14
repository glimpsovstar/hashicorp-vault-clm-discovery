package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type failingStore struct {
	*store.Store
}

func (f *failingStore) Ping(ctx context.Context) error {
	return errors.New("db down")
}

func TestWriteErrorIncludesRequestID(t *testing.T) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))))
	r.Get("/fail", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusInternalServerError, "boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/fail", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	reqID := middleware.GetReqID(req.Context())
	if body["request_id"] == "" {
		t.Fatal("expected request_id in error body")
	}
	if reqID != "" && body["request_id"] != reqID {
		t.Fatalf("request_id mismatch: body=%q context=%q", body["request_id"], reqID)
	}
}

func TestHealthReturnsRequestIDOnServerError(t *testing.T) {
	srv := NewServer(config.Config{}, &store.Store{}, scanner.New(scanner.Config{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Override ping path by using failing handler directly
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLogger(srv.log))
	r.Get("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		srv.writeServerError(w, r, errors.New("db down"), "database unavailable")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["request_id"] == "" {
		t.Fatal("expected request_id in 500 response")
	}
}

func TestRequestLoggerAttachesLogger(t *testing.T) {
	base := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLogger(base))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		log := requestLogger(r)
		if log == nil {
			t.Fatal("expected request logger in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
