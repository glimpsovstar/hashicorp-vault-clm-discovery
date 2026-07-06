package eventbus

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeStore struct {
	mu        sync.Mutex
	events    []store.Event
	delivered []uuid.UUID
	failed    map[uuid.UUID]string
	listErr   error
}

func (f *fakeStore) ListUndeliveredEvents(_ context.Context, _, _ int) ([]store.Event, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.events, nil
}

func (f *fakeStore) MarkEventDelivered(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = append(f.delivered, id)
	return nil
}

func (f *fakeStore) MarkEventFailed(_ context.Context, id uuid.UUID, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed == nil {
		f.failed = map[uuid.UUID]string{}
	}
	f.failed[id] = errMsg
	return nil
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func event() store.Event {
	return store.Event{ID: uuid.New(), EventType: "cert.revoked", Payload: json.RawMessage(`{"source":"ocsp"}`), CreatedAt: time.Now()}
}

func TestConfigured(t *testing.T) {
	t.Parallel()
	if New(Config{}, &fakeStore{}, testLogger()).Configured() {
		t.Fatal("no URL should be unconfigured")
	}
	if !New(Config{WebhookURL: "http://x"}, &fakeStore{}, testLogger()).Configured() {
		t.Fatal("URL should be configured")
	}
}

func TestRunOnce_DeliversAndMarks(t *testing.T) {
	t.Parallel()

	var got []store.Event
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token")
		}
		var e store.Event
		_ = json.NewDecoder(r.Body).Decode(&e)
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	fs := &fakeStore{events: []store.Event{event(), event()}}
	d := New(Config{WebhookURL: srv.URL, Token: "tok"}, fs, testLogger())

	delivered, failed, err := d.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if delivered != 2 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d, want 2/0", delivered, failed)
	}
	if len(fs.delivered) != 2 {
		t.Fatalf("marked delivered = %d, want 2", len(fs.delivered))
	}
	if len(got) != 2 || got[0].EventType != "cert.revoked" {
		t.Fatalf("webhook received %d events; unexpected content", len(got))
	}
}

func TestRunOnce_WebhookErrorMarksFailed(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := event()
	fs := &fakeStore{events: []store.Event{e}}
	d := New(Config{WebhookURL: srv.URL}, fs, testLogger())

	delivered, failed, err := d.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if delivered != 0 || failed != 1 {
		t.Fatalf("delivered=%d failed=%d, want 0/1", delivered, failed)
	}
	if _, ok := fs.failed[e.ID]; !ok {
		t.Fatal("expected the event to be marked failed")
	}
	if len(fs.delivered) != 0 {
		t.Fatal("failed event must not be marked delivered")
	}
}

func TestRunOnce_EmptyIsNoop(t *testing.T) {
	t.Parallel()

	d := New(Config{WebhookURL: "http://unused"}, &fakeStore{}, testLogger())
	delivered, failed, err := d.RunOnce(context.Background())
	if err != nil || delivered != 0 || failed != 0 {
		t.Fatalf("empty batch: delivered=%d failed=%d err=%v", delivered, failed, err)
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	d := New(Config{WebhookURL: "http://unused", Interval: time.Millisecond}, &fakeStore{}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop on context cancel")
	}
}
