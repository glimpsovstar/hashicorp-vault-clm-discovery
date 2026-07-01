package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_SetsHTTPTimeout(t *testing.T) {
	t.Parallel()

	// The client must not use http.DefaultClient (no timeout): a black-holed
	// Vault would otherwise wedge the post-scan reconcile goroutine forever.
	client, err := NewClient(Config{Address: "https://vault.example.com"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.http.Timeout <= 0 {
		t.Fatalf("client HTTP timeout = %v, want > 0", client.http.Timeout)
	}
}

func TestClient_ListMounts_Authenticated(t *testing.T) {
	t.Parallel()

	const wantToken = "test-token"
	mountsBody := map[string]interface{}{
		"pki/": map[string]interface{}{
			"type": "pki",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/v1/sys/mounts" {
			t.Errorf("path = %q, want /v1/sys/mounts", r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != wantToken {
			t.Errorf("X-Vault-Token = %q, want %q", got, wantToken)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mountsBody)
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{
		Address: srv.URL,
		Token:   wantToken,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !client.Configured() {
		t.Fatal("expected client to be configured")
	}

	got, err := client.ListMounts(context.Background())
	if err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil mounts map")
	}
	if _, ok := got["pki/"]; !ok {
		t.Fatalf("mounts = %#v, want pki/ entry", got)
	}
}
