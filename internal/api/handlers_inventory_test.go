package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestHandleInventory(t *testing.T) {
	t.Parallel()

	res := &fakeResourceStore{renewable: []store.Certificate{
		renewableCert("app.example.com", "web-server"),
	}}
	srv := newResourceServer(res)

	req := httptest.NewRequest(http.MethodGet, "/inventory?within_days=30", nil)
	rec := httptest.NewRecorder()
	srv.handleInventory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if res.gotWithinDays != 30 {
		t.Fatalf("within_days passed to store = %d, want 30", res.gotWithinDays)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	meta, ok := doc["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("_meta missing: %s", rec.Body.String())
	}
	hostvars, _ := meta["hostvars"].(map[string]any)
	if _, ok := hostvars["app.example.com"]; !ok {
		t.Fatalf("expected app.example.com in hostvars: %s", rec.Body.String())
	}
}

func TestHandleInventory_ListError(t *testing.T) {
	t.Parallel()

	srv := newResourceServer(&fakeResourceStore{renewableErr: context.Canceled})
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	rec := httptest.NewRecorder()
	srv.handleInventory(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestHandleInventory_DefaultsToAll(t *testing.T) {
	t.Parallel()

	res := &fakeResourceStore{}
	srv := newResourceServer(res)
	req := httptest.NewRequest(http.MethodGet, "/inventory", nil) // no within_days
	rec := httptest.NewRecorder()
	srv.handleInventory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if res.gotWithinDays <= 365 {
		t.Fatalf("default within_days = %d, want a large 'all' window", res.gotWithinDays)
	}
}
