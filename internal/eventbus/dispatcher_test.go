package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakeStore struct {
	mu             sync.Mutex
	events         []store.Event
	delivered      []uuid.UUID
	failed         map[uuid.UUID]string
	listErr        error
	deliveredErr   error
	gotBatch       int
	gotMaxAttempts int
}

func (f *fakeStore) ClaimUndeliveredEvents(_ context.Context, _ string, _ time.Duration, limit, maxAttempts int) ([]store.Event, error) {
	f.gotBatch = limit
	f.gotMaxAttempts = maxAttempts
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.events, nil
}

func (f *fakeStore) MarkEventDelivered(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deliveredErr != nil {
		return f.deliveredErr
	}
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
	if !New(Config{ITSMWebhookURL: "http://itsm"}, &fakeStore{}, testLogger()).Configured() {
		t.Fatal("ITSM-only should be configured")
	}
}

func TestRunOnce_ITSMOnlyDelivers(t *testing.T) {
	t.Parallel()

	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	fs := &fakeStore{events: []store.Event{event()}}
	d := New(Config{ITSMWebhookURL: srv.URL}, fs, testLogger())
	delivered, failed, err := d.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if delivered != 1 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d", delivered, failed)
	}
	if !strings.Contains(got, `"source":"clm"`) || !strings.Contains(got, "cert.revoked") {
		t.Fatalf("itsm body = %s", got)
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

func TestRunOnce_ListErrorAborts(t *testing.T) {
	t.Parallel()

	fs := &fakeStore{listErr: context.Canceled}
	d := New(Config{WebhookURL: "http://unused"}, fs, testLogger())
	if _, _, err := d.RunOnce(context.Background()); err == nil {
		t.Fatal("expected RunOnce to return the store read error")
	}
}

func TestRunOnce_MarkDeliveredFailureCountsFailed(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	e := event()
	fs := &fakeStore{events: []store.Event{e}, deliveredErr: context.Canceled}
	d := New(Config{WebhookURL: srv.URL}, fs, testLogger())

	delivered, failed, err := d.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// Posted OK but couldn't record delivery -> treated as failed so the
	// dead-letter cap bounds redelivery.
	if delivered != 0 || failed != 1 {
		t.Fatalf("delivered=%d failed=%d, want 0/1", delivered, failed)
	}
	if _, ok := fs.failed[e.ID]; !ok {
		t.Fatal("expected the event to be marked failed when delivery couldn't be recorded")
	}
}

func TestRunOnce_NoTokenNoAuthHeader(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization header should be absent when no token is configured")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fs := &fakeStore{events: []store.Event{event()}}
	d := New(Config{WebhookURL: srv.URL}, fs, testLogger())
	if _, _, err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
}

func TestNew_Defaults(t *testing.T) {
	t.Parallel()

	fs := &fakeStore{}
	d := New(Config{WebhookURL: "http://unused"}, fs, testLogger())
	if _, _, err := d.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if fs.gotBatch != 50 || fs.gotMaxAttempts != 10 {
		t.Fatalf("defaults not applied: batch=%d maxAttempts=%d, want 50/10", fs.gotBatch, fs.gotMaxAttempts)
	}
	if d.cfg.Interval != 15*time.Second {
		t.Fatalf("interval default = %v, want 15s", d.cfg.Interval)
	}
}

func TestPing_PostsConnectionTestEvent(t *testing.T) {
	t.Parallel()

	var (
		gotMethod, gotAuth string
		gotBody            map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if err := Ping(context.Background(), srv.URL, "tok"); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s, want POST", gotMethod)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want Bearer", gotAuth)
	}
	if gotBody["event_type"] != "clm.connection.test" {
		t.Fatalf("event_type = %v", gotBody["event_type"])
	}
	if _, err := uuid.Parse(fmt.Sprint(gotBody["id"])); err != nil {
		t.Fatalf("id = %v: %v", gotBody["id"], err)
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(gotBody["created_at"])); err != nil {
		t.Fatalf("created_at = %v: %v", gotBody["created_at"], err)
	}
}

func TestPing_NoTokenOmitsAuthorization(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization should be absent")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := Ping(context.Background(), srv.URL, ""); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}
