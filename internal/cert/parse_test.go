package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseCertificateSelfSigned(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{"test.local", "*.test.local"},
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

	parsed := ParseCertificate(raw, []*x509.Certificate{raw}, "test.local", "test.local")
	if parsed.FingerprintSHA256 == "" {
		t.Fatal("expected fingerprint")
	}
	if parsed.ChainStatus != ChainSelfSigned {
		t.Fatalf("expected self_signed, got %s", parsed.ChainStatus)
	}
	if !parsed.HostnameMatchesSAN {
		t.Fatal("expected hostname match")
	}
	if parsed.PEM == "" {
		t.Fatal("expected pem")
	}

	block, _ := pem.Decode([]byte(parsed.PEM))
	if block == nil {
		t.Fatal("invalid pem")
	}
}

func TestHostnameMatchesSANWildcard(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"*.example.com"},
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	raw, _ := x509.ParseCertificate(der)

	parsed := ParseCertificate(raw, []*x509.Certificate{raw}, "app.example.com", "app.example.com")
	if !parsed.HostnameMatchesSAN {
		t.Fatal("expected wildcard match")
	}
}
