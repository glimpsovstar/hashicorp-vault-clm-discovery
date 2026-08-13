package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewServer_OnlyReadIdentityLeavesImporterNil(t *testing.T) {
	t.Parallel()

	srv := NewServer(config.Config{
		VaultAddr:  "http://vault.example:8200",
		VaultToken: "hvs.read-only",
	}, &store.Store{}, scanner.New(scanner.Config{}), discardLogger())
	if srv.reconciler == nil {
		t.Fatal("reconciler must use the read identity")
	}
	if srv.importer != nil {
		t.Fatal("importer must stay nil when only the read identity is configured")
	}
}

func TestNewServer_ImportUsesImportIdentityWhenBothConfigured(t *testing.T) {
	t.Parallel()

	const (
		readToken   = "hvs.read-only"
		importToken = "hvs.import-write"
	)

	var mountsToken, bundleToken string
	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
			mountsToken = r.Header.Get("X-Vault-Token")
			// 500 so Reconcile returns before touching the nil store pool.
			http.Error(w, "unavailable", http.StatusInternalServerError)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/pki/issuers/import/bundle":
			bundleToken = r.Header.Get("X-Vault-Token")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"imported_issuers":["iss-1"],"imported_keys":[],"mapping":{}}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(vaultSrv.Close)

	srv := NewServer(config.Config{
		VaultAddr:        vaultSrv.URL,
		VaultToken:       readToken,
		VaultImportToken: importToken,
	}, &store.Store{}, scanner.New(scanner.Config{}), discardLogger())
	if srv.importer == nil {
		t.Fatal("importer must be wired when import identity is configured")
	}
	if srv.reconciler == nil {
		t.Fatal("reconciler must be wired from the read identity")
	}

	if _, err := srv.importer.ImportIssuerBundle(context.Background(), "pki", "pem"); err != nil {
		t.Fatalf("ImportIssuerBundle: %v", err)
	}
	_, _ = srv.reconciler.Reconcile(context.Background())

	if bundleToken != importToken {
		t.Fatalf("issuers/import/bundle X-Vault-Token = %q, want import %q", bundleToken, importToken)
	}
	if mountsToken != readToken {
		t.Fatalf("sys/mounts X-Vault-Token = %q, want read %q", mountsToken, readToken)
	}
}

func TestHandleImportIssuer_ImportIdentityNotConfigured(t *testing.T) {
	t.Parallel()

	ca := store.Issuer{IsCA: true, PEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"}
	srv := NewServer(openTestConfig(config.Config{
		VaultAddr:  "http://vault.example:8200",
		VaultToken: "hvs.read-only",
	}), &store.Store{}, scanner.New(scanner.Config{}), discardLogger())
	srv.resources = &fakeResourceStore{issuer: ca}

	rec := httptest.NewRecorder()
	srv.handleImportIssuer(rec, idRequestBody(http.MethodPost, uuid.New().String(), `{"consent":true,"mount":"pki"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "import identity not configured" {
		t.Fatalf("error = %q, want import identity not configured", body["error"])
	}
}

func TestRenewExtraVarsOmitsVaultCredentials(t *testing.T) {
	t.Parallel()

	vars := renewExtraVars("app.example.com", store.RenewalConfig{Mount: "pki", Role: "web"})
	for _, key := range []string{
		"vault_token", "token", "role_id", "secret_id",
		"VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID",
		"VAULT_IMPORT_TOKEN", "VAULT_IMPORT_ROLE_ID", "VAULT_IMPORT_SECRET_ID",
	} {
		if _, ok := vars[key]; ok {
			t.Fatalf("extra_vars must not contain Vault credential %q: %#v", key, vars)
		}
	}
	joined := strings.ToLower(strings.Join(mapKeys(vars), ","))
	for _, secret := range []string{"hvs.", "role_id", "secret_id"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("extra_vars keys look like Vault creds: %#v", vars)
		}
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
