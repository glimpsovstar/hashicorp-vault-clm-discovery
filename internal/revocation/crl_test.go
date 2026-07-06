package revocation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testCA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM string
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return testCA{cert: cert, key: key, certPEM: pemStr}
}

// crlServer serves a CA-signed CRL revoking the given serials.
func crlServer(t *testing.T, ca testCA, revoked ...*big.Int) *httptest.Server {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckCRL_RevokedAndVerified(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	serial := big.NewInt(0x1234abcd)
	srv := crlServer(t, ca, serial)

	res, err := CheckCRL(context.Background(), srv.Client(), serial.Text(16), []string{srv.URL}, ca.certPEM)
	if err != nil {
		t.Fatalf("CheckCRL: %v", err)
	}
	if res.Status != StatusRevoked {
		t.Fatalf("status = %q, want revoked", res.Status)
	}
	if !res.Verified {
		t.Fatal("expected CRL signature verified against issuer")
	}
	if res.RevokedAt == nil {
		t.Fatal("expected RevokedAt set")
	}
}

func TestCheckCRL_GoodWhenNotListed(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	srv := crlServer(t, ca, big.NewInt(999)) // revokes a different serial

	res, err := CheckCRL(context.Background(), srv.Client(), big.NewInt(0x55).Text(16), []string{srv.URL}, ca.certPEM)
	if err != nil {
		t.Fatalf("CheckCRL: %v", err)
	}
	if res.Status != StatusGood {
		t.Fatalf("status = %q, want good", res.Status)
	}
	if !res.Verified {
		t.Fatal("expected verified")
	}
}

func TestCheckCRL_UnknownWhenNoDP(t *testing.T) {
	t.Parallel()

	res, err := CheckCRL(context.Background(), http.DefaultClient, "abcd", nil, "")
	if err != nil {
		t.Fatalf("CheckCRL: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
}

func TestCheckCRL_UnverifiedWithWrongIssuer(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	other := newTestCA(t) // different key/cert
	serial := big.NewInt(0x42)
	srv := crlServer(t, ca, serial)

	res, err := CheckCRL(context.Background(), srv.Client(), serial.Text(16), []string{srv.URL}, other.certPEM)
	if err != nil {
		t.Fatalf("CheckCRL: %v", err)
	}
	if res.Status != StatusRevoked {
		t.Fatalf("status = %q, want revoked (membership still matches)", res.Status)
	}
	if res.Verified {
		t.Fatal("expected verified=false with the wrong issuer")
	}
}

func TestCheckCRL_InvalidSerial(t *testing.T) {
	t.Parallel()

	if _, err := CheckCRL(context.Background(), http.DefaultClient, "zzzz", []string{"http://x"}, ""); err == nil {
		t.Fatal("expected error for invalid serial")
	}
}

func TestCheckCRL_RejectsNonHTTPScheme(t *testing.T) {
	t.Parallel()

	// A file:// (or other non-http) CRL URL must not be fetched; with no usable
	// DP the result is unknown, not an SSRF/file read.
	res, err := CheckCRL(context.Background(), http.DefaultClient, big.NewInt(1).Text(16), []string{"file:///etc/passwd"}, "")
	if err != nil {
		t.Fatalf("CheckCRL: %v", err)
	}
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown for non-http scheme", res.Status)
	}
}
