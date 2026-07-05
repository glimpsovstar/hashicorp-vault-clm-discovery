package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestImportIssuerBundle_Success(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/pki/issuers/import/bundle" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != "rw-token" {
			t.Fatalf("token header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"imported_issuers":["abc-123"],"imported_keys":["key-1"],"mapping":{"abc-123":"key-1"}}}`))
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(Config{Address: srv.URL, Token: "rw-token"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.ImportIssuerBundle(context.Background(), "pki", "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----")
	if err != nil {
		t.Fatalf("ImportIssuerBundle: %v", err)
	}
	if len(res.ImportedIssuers) != 1 || res.ImportedIssuers[0] != "abc-123" {
		t.Fatalf("imported_issuers = %v, want [abc-123]", res.ImportedIssuers)
	}
}

func TestImportIssuerBundle_VaultError(t *testing.T) {
	t.Parallel()

	// A read-only token yields 403; the client must surface it as an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(Config{Address: srv.URL, Token: "ro-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportIssuerBundle(context.Background(), "pki", "pem"); err == nil {
		t.Fatal("expected error on Vault 403")
	}
}
