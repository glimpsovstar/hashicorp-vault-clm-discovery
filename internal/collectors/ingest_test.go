package collectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
)

type fakeUpsert struct {
	calls []cert.ParsedCertificate
	ids   map[string]uuid.UUID
}

func (f *fakeUpsert) UpsertCertificate(_ context.Context, _ uuid.UUID, parsed cert.ParsedCertificate, _ cert.Observation) (uuid.UUID, error) {
	if f.ids == nil {
		f.ids = map[string]uuid.UUID{}
	}
	if id, ok := f.ids[parsed.FingerprintSHA256]; ok {
		f.calls = append(f.calls, parsed)
		return id, nil
	}
	id := uuid.New()
	f.ids[parsed.FingerprintSHA256] = id
	f.calls = append(f.calls, parsed)
	return id, nil
}

func mustLeafPEM(t *testing.T) (pemText string, fp string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "cloud.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"cloud.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
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
	parsed := cert.ParseCertificate(raw, []*x509.Certificate{raw}, "cloud.example.com", "cloud.example.com")
	return parsed.PEM, parsed.FingerprintSHA256
}

func TestIngestPublicPEMs_UpsertsByFingerprint(t *testing.T) {
	t.Parallel()

	pemText, fp := mustLeafPEM(t)
	up := &fakeUpsert{}
	scanID := uuid.New()

	n, skipped, err := IngestPublicPEMs(context.Background(), up, scanID, "cloud_akv", []Item{{PEM: pemText, Name: "app-cert"}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || skipped != 0 {
		t.Fatalf("ingested=%d skipped=%d", n, skipped)
	}
	if up.calls[0].FingerprintSHA256 != fp {
		t.Fatalf("fp = %s, want %s", up.calls[0].FingerprintSHA256, fp)
	}

	n2, _, err := IngestPublicPEMs(context.Background(), up, scanID, "cloud_akv", []Item{{PEM: pemText}})
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 1 {
		t.Fatalf("second ingest = %d", n2)
	}
	if len(up.ids) != 1 {
		t.Fatalf("want one fingerprint id, got %d", len(up.ids))
	}
}

func TestIngestPublicPEMs_RejectsPrivateKey(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	leaf, _ := mustLeafPEM(t)
	combined := leaf + string(keyPEM)

	_, _, err = IngestPublicPEMs(context.Background(), &fakeUpsert{}, uuid.New(), "cloud_akv", []Item{{PEM: combined}})
	if err != ErrPrivateKeyRejected {
		t.Fatalf("err = %v, want ErrPrivateKeyRejected", err)
	}
}

func TestIngestPublicPEMs_InvalidSource(t *testing.T) {
	t.Parallel()
	_, _, err := IngestPublicPEMs(context.Background(), &fakeUpsert{}, uuid.New(), "network", []Item{})
	if err == nil {
		t.Fatal("expected invalid source")
	}
}
