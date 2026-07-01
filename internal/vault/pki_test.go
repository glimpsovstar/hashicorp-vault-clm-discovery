package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
)

func testCertPEM(t *testing.T) (string, *x509.Certificate) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "vault-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"vault-test.local"},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), raw
}

func TestClient_ListPKIMounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mounts  map[string]interface{}
		want    []string
		wantErr bool
	}{
		{
			name: "filters pki mounts only",
			mounts: map[string]interface{}{
				"pki/": map[string]interface{}{
					"type": "pki",
				},
				"secret/": map[string]interface{}{
					"type": "kv",
				},
			},
			want: []string{"pki/"},
		},
		{
			name: "no pki mounts",
			mounts: map[string]interface{}{
				"secret/": map[string]interface{}{
					"type": "kv",
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/mounts" {
					t.Errorf("path = %q, want /v1/sys/mounts", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.mounts)
			}))
			t.Cleanup(srv.Close)

			client, err := NewClient(Config{Address: srv.URL, Token: "tok"})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			got, err := client.ListPKIMounts(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListPKIMounts error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("ListPKIMounts = %#v, want %#v", got, tt.want)
			}
			for _, path := range tt.want {
				found := false
				for _, g := range got {
					if g == path {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("ListPKIMounts = %#v, missing %q", got, path)
				}
			}
		})
	}
}

func TestClient_ListCertSerials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mount     string
		wantPath  string
		keys      []string
		want      []string
	}{
		{
			name:     "with trailing slash",
			mount:    "pki/",
			wantPath: "/v1/pki/certs",
			keys:     []string{"01:ab:cd", "02:ef:gh"},
			want:     []string{"01:ab:cd", "02:ef:gh"},
		},
		{
			name:     "normalizes mount without slash",
			mount:    "pki",
			wantPath: "/v1/pki/certs",
			keys:     []string{"serial-1"},
			want:     []string{"serial-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.wantPath {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.wantPath)
				}
				// Vault's PKI cert-list endpoint only answers a LIST operation:
				// either the LIST verb or a GET with ?list=true. A plain GET
				// returns 405, so assert the request carries list semantics.
				if r.Method != "LIST" && r.URL.Query().Get("list") != "true" {
					t.Errorf("method = %q, query list = %q; want LIST verb or ?list=true", r.Method, r.URL.Query().Get("list"))
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"keys": tt.keys,
					},
				})
			}))
			t.Cleanup(srv.Close)

			client, err := NewClient(Config{Address: srv.URL})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			got, err := client.ListCertSerials(context.Background(), tt.mount)
			if err != nil {
				t.Fatalf("ListCertSerials: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ListCertSerials = %#v, want %#v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("ListCertSerials[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestClient_ReadCert(t *testing.T) {
	t.Parallel()

	const serial = "01:ab:cd:ef"
	pemStr, raw := testCertPEM(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/v1/pki/cert/" + serial
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate":   pemStr,
				"serial_number": serial,
				"revocation_time": 0,
			},
		})
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{Address: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	gotPEM, meta, err := client.ReadCert(context.Background(), "pki", serial)
	if err != nil {
		t.Fatalf("ReadCert: %v", err)
	}
	if gotPEM != pemStr {
		t.Fatal("ReadCert returned unexpected PEM")
	}
	if meta["serial_number"] != serial {
		t.Fatalf("metadata serial_number = %v, want %q", meta["serial_number"], serial)
	}

	fp, err := FingerprintSHA256FromPEM(gotPEM)
	if err != nil {
		t.Fatalf("FingerprintSHA256FromPEM: %v", err)
	}

	parsed := cert.ParseCertificate(raw, []*x509.Certificate{raw}, "vault-test.local", "vault-test.local")
	if fp != parsed.FingerprintSHA256 {
		t.Fatalf("fingerprint = %q, want %q (cert.ParseCertificate)", fp, parsed.FingerprintSHA256)
	}
}

func TestFingerprintSHA256FromPEM(t *testing.T) {
	t.Parallel()

	pemStr, raw := testCertPEM(t)

	got, err := FingerprintSHA256FromPEM(pemStr)
	if err != nil {
		t.Fatalf("FingerprintSHA256FromPEM: %v", err)
	}

	parsed := cert.ParseCertificate(raw, []*x509.Certificate{raw}, "vault-test.local", "vault-test.local")
	if got != parsed.FingerprintSHA256 {
		t.Fatalf("fingerprint = %q, want %q", got, parsed.FingerprintSHA256)
	}
}

func TestFingerprintSHA256FromPEM_Invalid(t *testing.T) {
	t.Parallel()

	_, err := FingerprintSHA256FromPEM("not a pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
