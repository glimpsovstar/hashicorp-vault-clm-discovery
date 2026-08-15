package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestHandleListEvents(t *testing.T) {
	t.Parallel()

	certID := uuid.New()
	res := &fakeResourceStore{events: []store.Event{
		{ID: uuid.New(), EventType: "cert.revoked", CertificateID: &certID, Payload: json.RawMessage(`{"source":"ocsp"}`)},
	}}
	srv := newResourceServer(res)

	req := httptest.NewRequest(http.MethodGet, "/events?limit=50", nil)
	rec := httptest.NewRecorder()
	srv.handleListEvents(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []store.Event `json:"items"`
		Limit int           `json:"limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].EventType != "cert.revoked" {
		t.Fatalf("unexpected events: %s", rec.Body.String())
	}
	if resp.Limit != 50 {
		t.Fatalf("limit = %d, want 50", resp.Limit)
	}
}

func TestHandleListEvents_FilterEventType(t *testing.T) {
	t.Parallel()
	res := &fakeResourceStore{events: []store.Event{
		{ID: uuid.New(), EventType: "cert.revoked"},
		{ID: uuid.New(), EventType: "cert.discovered"},
	}}
	srv := newResourceServer(res)
	req := httptest.NewRequest(http.MethodGet, "/events?event_type=cert.discovered", nil)
	rec := httptest.NewRecorder()
	srv.handleListEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Items []store.Event `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 1 || resp.Items[0].EventType != "cert.discovered" {
		t.Fatalf("items=%s", rec.Body.String())
	}
}

func TestHandleListEvents_Error(t *testing.T) {
	t.Parallel()

	srv := newResourceServer(&fakeResourceStore{eventsErr: context.Canceled})
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rec := httptest.NewRecorder()
	srv.handleListEvents(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
