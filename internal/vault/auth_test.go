package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClient_AppRoleLogin_ThenListMountsSendsClientToken(t *testing.T) {
	t.Parallel()

	const (
		roleID      = "role-uuid"
		secretID    = "secret-uuid"
		clientToken = "hvs.approle-client-token"
		ns          = "admin"
	)

	var loginHits, mountsHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Namespace"); got != ns {
			t.Errorf("X-Vault-Namespace = %q, want %q", got, ns)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			loginHits.Add(1)
			if got := r.Header.Get("X-Vault-Token"); got != "" {
				t.Errorf("login must not send X-Vault-Token, got %q", got)
			}
			var body struct {
				RoleID   string `json:"role_id"`
				SecretID string `json:"secret_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode login: %v", err)
			}
			if body.RoleID != roleID || body.SecretID != secretID {
				t.Errorf("login body role_id=%q secret_id=%q", body.RoleID, body.SecretID)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   clientToken,
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
			mountsHits.Add(1)
			if got := r.Header.Get("X-Vault-Token"); got != clientToken {
				t.Errorf("X-Vault-Token = %q, want %q", got, clientToken)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pki/": map[string]any{"type": "pki"},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{
		Address:    srv.URL,
		Namespace:  ns,
		AuthMethod: "approle",
		RoleID:     roleID,
		SecretID:   secretID,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	got, err := client.ListMounts(ctx)
	if err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if _, ok := got["pki/"]; !ok {
		t.Fatalf("mounts = %#v, want pki/ entry", got)
	}
	if n := loginHits.Load(); n != 1 {
		t.Fatalf("approle login hits = %d, want 1", n)
	}
	if n := mountsHits.Load(); n != 1 {
		t.Fatalf("sys/mounts hits = %d, want 1", n)
	}
}

func TestClient_TokenAuth_ListMountsWithoutLogin(t *testing.T) {
	t.Parallel()

	const wantToken = "static-token"
	var loginHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			loginHits.Add(1)
			http.Error(w, "login must not be called for token auth", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/mounts" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("X-Vault-Token"); got != wantToken {
			t.Errorf("X-Vault-Token = %q, want %q", got, wantToken)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pki/": map[string]any{"type": "pki"},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{
		Address:    srv.URL,
		Token:      wantToken,
		AuthMethod: "token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()
	if err := client.EnsureToken(ctx); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	if _, err := client.ListMounts(ctx); err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if n := loginHits.Load(); n != 0 {
		t.Fatalf("approle login hits = %d, want 0", n)
	}
}

func TestClient_EnsureToken_RenewsBeforeExpiry(t *testing.T) {
	t.Parallel()

	const (
		roleID       = "role-uuid"
		secretID     = "secret-uuid"
		clientToken  = "hvs.approle-client-token"
		renewedToken = "hvs.approle-renewed-token"
	)

	var loginHits, renewHits, mountsHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			loginHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   clientToken,
					"lease_duration": 1,
					"renewable":      true,
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/renew-self":
			renewHits.Add(1)
			if got := r.Header.Get("X-Vault-Token"); got != clientToken {
				t.Errorf("renew X-Vault-Token = %q, want %q", got, clientToken)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   renewedToken,
					"lease_duration": 3600,
					"renewable":      true,
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
			mountsHits.Add(1)
			if got := r.Header.Get("X-Vault-Token"); got != renewedToken {
				t.Errorf("X-Vault-Token = %q, want renewed %q", got, renewedToken)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pki/": map[string]any{"type": "pki"},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{
		Address:    srv.URL,
		AuthMethod: "approle",
		RoleID:     roleID,
		SecretID:   secretID,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := client.EnsureToken(ctx); err != nil {
		t.Fatalf("EnsureToken: %v", err)
	}
	if _, err := client.ListMounts(ctx); err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if n := loginHits.Load(); n != 1 {
		t.Fatalf("approle login hits = %d, want 1", n)
	}
	if n := renewHits.Load(); n != 1 {
		t.Fatalf("renew-self hits = %d, want 1", n)
	}
	if n := mountsHits.Load(); n != 1 {
		t.Fatalf("sys/mounts hits = %d, want 1", n)
	}
}

func TestClient_Login_AppRoleRequiresCredentials(t *testing.T) {
	t.Parallel()

	client, err := NewClient(Config{
		Address:    "https://vault.example.com",
		AuthMethod: "approle",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Login(context.Background()); err == nil {
		t.Fatal("expected error when role_id and secret_id are empty")
	}
}
