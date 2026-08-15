package cloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
)

type memSource struct {
	certs map[string]string
	err   error
}

func (m *memSource) List(context.Context) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	var names []string
	for n := range m.certs {
		names = append(names, n)
	}
	return names, nil
}

func (m *memSource) GetPublicPEM(_ context.Context, name string) (string, error) {
	return m.certs[name], nil
}

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

func TestCollect_UpsertsFingerprintNoKeys(t *testing.T) {
	t.Parallel()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "akv.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"akv.example.com"},
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	raw, _ := x509.ParseCertificate(der)
	parsed := cert.ParseCertificate(raw, []*x509.Certificate{raw}, "akv.example.com", "akv.example.com")

	up := &fakeUpsert{}
	src := &memSource{certs: map[string]string{"app-cert": parsed.PEM}}
	n, skipped, err := Collect(context.Background(), up, uuid.New(), "cloud_akv", src)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || skipped != 0 {
		t.Fatalf("ingested=%d skipped=%d", n, skipped)
	}
	if _, ok := up.fps[parsed.FingerprintSHA256]; !ok {
		t.Fatal("expected fingerprint upsert")
	}
	// Interface has no GetKey — document by type assertion absence in compile.
	var _ collectors.Upserter = up
}
