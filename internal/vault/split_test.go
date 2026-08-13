package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSplitIdentities_ImportTokenDiffersFromReadToken(t *testing.T) {
	t.Parallel()

	const (
		readToken   = "hvs.read-only"
		importToken = "hvs.import-write"
	)

	var mountsToken, bundleToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
			mountsToken = r.Header.Get("X-Vault-Token")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pki/": map[string]any{"type": "pki"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/pki/issuers/import/bundle":
			bundleToken = r.Header.Get("X-Vault-Token")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"imported_issuers":["iss-1"],"imported_keys":[],"mapping":{}}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	readClient, err := NewClient(Config{Address: srv.URL, Token: readToken, AuthMethod: "token"})
	if err != nil {
		t.Fatalf("read NewClient: %v", err)
	}
	importClient, err := NewClient(Config{Address: srv.URL, Token: importToken, AuthMethod: "token"})
	if err != nil {
		t.Fatalf("import NewClient: %v", err)
	}

	if _, err := readClient.ListMounts(context.Background()); err != nil {
		t.Fatalf("ListMounts: %v", err)
	}
	if _, err := importClient.ImportIssuerBundle(context.Background(), "pki", "pem"); err != nil {
		t.Fatalf("ImportIssuerBundle: %v", err)
	}
	if mountsToken != readToken {
		t.Fatalf("sys/mounts X-Vault-Token = %q, want read %q", mountsToken, readToken)
	}
	if bundleToken != importToken {
		t.Fatalf("issuers/import/bundle X-Vault-Token = %q, want import %q", bundleToken, importToken)
	}
	if mountsToken == bundleToken {
		t.Fatal("read and import identities must send different tokens")
	}
}

func TestImportIssuerBundle_AppRoleLoginThenClientToken(t *testing.T) {
	t.Parallel()

	const (
		roleID      = "import-role"
		secretID    = "import-secret"
		clientToken = "hvs.import-approle-token"
	)

	var loginHits, importHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case r.Method == http.MethodPost && r.URL.Path == "/v1/pki/issuers/import/bundle":
			importHits.Add(1)
			if got := r.Header.Get("X-Vault-Token"); got != clientToken {
				t.Errorf("X-Vault-Token = %q, want %q", got, clientToken)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"imported_issuers":["iss-1"],"imported_keys":[],"mapping":{}}}`))
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
	if _, err := client.ImportIssuerBundle(context.Background(), "pki", "pem"); err != nil {
		t.Fatalf("ImportIssuerBundle: %v", err)
	}
	if n := loginHits.Load(); n != 1 {
		t.Fatalf("approle login hits = %d, want 1", n)
	}
	if n := importHits.Load(); n != 1 {
		t.Fatalf("import/bundle hits = %d, want 1", n)
	}
}
