package itsm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestRender_CatalogueTemplates(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	ev := store.Event{
		ID:        id,
		EventType: "cert.expiring",
		Payload:   json.RawMessage(`{"certificate_id":"` + id.String() + `","days_until_expiry":7}`),
		CreatedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
	}
	body, err := Render(ev)
	if err != nil {
		t.Fatal(err)
	}
	var ticket map[string]any
	if err := json.Unmarshal(body, &ticket); err != nil {
		t.Fatal(err)
	}
	if ticket["source"] != "clm" {
		t.Fatalf("source = %v, want clm", ticket["source"])
	}
	if ticket["event_type"] != "cert.expiring" {
		t.Fatalf("event_type = %v", ticket["event_type"])
	}
	if ticket["event_id"] != id.String() {
		t.Fatalf("event_id = %v", ticket["event_id"])
	}
	if ticket["summary"] == "" {
		t.Fatal("expected summary template")
	}
	if !strings.Contains(ticket["summary"].(string), "expiring") {
		t.Fatalf("summary = %v", ticket["summary"])
	}
}

func TestSink_DeliverPostsTemplateAndHMAC(t *testing.T) {
	t.Parallel()

	secret := "test-hmac-secret"
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-CLM-Signature")
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	sink := New(Config{WebhookURL: srv.URL, HMACSecret: secret})
	ev := store.Event{
		ID:        uuid.New(),
		EventType: "cert.revoked",
		Payload:   json.RawMessage(`{"certificate_id":"x","source":"ocsp"}`),
		CreatedAt: time.Now().UTC(),
	}
	if err := sink.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("signature = %q, want %q", gotSig, want)
	}
	if !strings.Contains(string(gotBody), `"event_type":"cert.revoked"`) {
		t.Fatalf("body = %s", gotBody)
	}
}

func TestSink_NotConfigured(t *testing.T) {
	t.Parallel()
	sink := New(Config{})
	if sink.Configured() {
		t.Fatal("empty URL should not be configured")
	}
	err := sink.Deliver(context.Background(), store.Event{EventType: "cert.discovered"})
	if err == nil {
		t.Fatal("expected error")
	}
}
