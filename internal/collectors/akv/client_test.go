package akv

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
)

type fakeUpsert struct {
	fps map[string]uuid.UUID
}

func (f *fakeUpsert) UpsertCertificate(_ context.Context, _ uuid.UUID, parsed cert.ParsedCertificate, _ cert.Observation) (uuid.UUID, error) {
	if f.fps == nil {
		f.fps = map[string]uuid.UUID{}
	}
	if id, ok := f.fps[parsed.FingerprintSHA256]; ok {
		return id, nil
	}
	id := uuid.New()
	f.fps[parsed.FingerprintSHA256] = id
	return id, nil
}

func TestCollectAKV_UpsertsFingerprint(t *testing.T) {
	t.Parallel()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "akv-live.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"akv-live.example.com"},
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	raw, _ := x509.ParseCertificate(der)
	parsed := cert.ParseCertificate(raw, []*x509.Certificate{raw}, "akv-live.example.com", "akv-live.example.com")
	cerB64 := base64.StdEncoding.EncodeToString(der)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing bearer")
		}
		switch {
		case r.URL.Path == "/certificates" && r.URL.Query().Get("api-version") == "7.4":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{
					{"id": "https://example.vault.azure.net/certificates/app-cert"},
				},
			})
		case r.URL.Path == "/certificates/app-cert":
			_ = json.NewEncoder(w).Encode(map[string]string{"cer": cerB64})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	src := &VaultSource{VaultURI: srv.URL, Token: "test-token", HTTP: srv.Client()}
	up := &fakeUpsert{}
	n, skipped, err := Collect(context.Background(), up, uuid.New(), src)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || skipped != 0 {
		t.Fatalf("ingested=%d skipped=%d", n, skipped)
	}
	if _, ok := up.fps[parsed.FingerprintSHA256]; !ok {
		t.Fatal("expected fingerprint upsert")
	}
}
