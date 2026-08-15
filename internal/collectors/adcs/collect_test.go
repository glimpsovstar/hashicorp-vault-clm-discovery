package adcs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
)

type fakeCtrl struct {
	configured bool
	tmplID     int
	jobID      int
	extraVars  map[string]any
	stdout     []byte
	status     aap.Status
}

func (f *fakeCtrl) Configured() bool { return f.configured }
func (f *fakeCtrl) FindJobTemplate(context.Context, string) (int, error) {
	return f.tmplID, nil
}
func (f *fakeCtrl) LaunchJobTemplate(_ context.Context, _ int, extraVars map[string]any) (aap.LaunchResult, error) {
	f.extraVars = extraVars
	return aap.LaunchResult{JobID: f.jobID}, nil
}
func (f *fakeCtrl) WaitForJob(context.Context, aap.LaunchResult, time.Duration) (aap.Status, error) {
	if f.status == "" {
		return aap.StatusSuccessful, nil
	}
	return f.status, nil
}
func (f *fakeCtrl) JobStdout(context.Context, int) ([]byte, error) { return f.stdout, nil }

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

func leafPEM(t *testing.T) (string, string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "adcs.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"adcs.example.com"},
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
	parsed := cert.ParseCertificate(raw, []*x509.Certificate{raw}, "adcs.example.com", "adcs.example.com")
	return parsed.PEM, parsed.FingerprintSHA256
}

func TestCollect_AAPPathIngestsPublicPEM(t *testing.T) {
	t.Parallel()
	pemText, fp := leafPEM(t)
	payload, _ := json.Marshal(map[string]any{
		"ca_host": "ca01.corp.example",
		"certificates": []map[string]string{
			{"pem": pemText, "request_id": "1"},
		},
	})
	ctrl := &fakeCtrl{configured: true, tmplID: 11, jobID: 22, stdout: payload}
	up := &fakeUpsert{}
	n, skipped, err := Collect(context.Background(), ctrl, up, uuid.New(), DefaultTemplate, "ca01.corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || skipped != 0 {
		t.Fatalf("ingested=%d skipped=%d", n, skipped)
	}
	if _, ok := up.fps[fp]; !ok {
		t.Fatal("expected fingerprint")
	}
	if ctrl.extraVars["ca_host"] != "ca01.corp.example" {
		t.Fatalf("extra_vars = %#v", ctrl.extraVars)
	}
	if _, ok := ctrl.extraVars["token"]; ok {
		t.Fatal("must not send token in extra_vars")
	}
	if _, ok := ctrl.extraVars["password"]; ok {
		t.Fatal("must not send password in extra_vars")
	}
}

func TestCollect_RejectsPrivateKeyInStdout(t *testing.T) {
	t.Parallel()
	pemText, _ := leafPEM(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	payload, _ := json.Marshal(map[string]any{
		"certificates": []map[string]string{{"pem": pemText + string(keyPEM)}},
	})
	ctrl := &fakeCtrl{configured: true, tmplID: 1, jobID: 2, stdout: payload}
	_, _, err := Collect(context.Background(), ctrl, &fakeUpsert{}, uuid.New(), DefaultTemplate, "ca01")
	if err != collectors.ErrPrivateKeyRejected {
		t.Fatalf("err = %v", err)
	}
}

func TestCollect_RequiresAAP(t *testing.T) {
	t.Parallel()
	_, _, err := Collect(context.Background(), &fakeCtrl{configured: false}, &fakeUpsert{}, uuid.New(), DefaultTemplate, "ca01")
	if err == nil {
		t.Fatal("expected error")
	}
}
