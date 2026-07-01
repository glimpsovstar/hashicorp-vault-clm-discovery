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

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type mockCertStore struct {
	certs map[string]store.ManagedStatusUpdate
}

func (m *mockCertStore) UpdateManagedStatusByFingerprint(_ context.Context, fingerprint string, u store.ManagedStatusUpdate) (bool, error) {
	if m.certs == nil {
		m.certs = make(map[string]store.ManagedStatusUpdate)
	}
	if _, ok := m.certs[fingerprint]; !ok {
		return false, nil
	}
	m.certs[fingerprint] = u
	return true, nil
}

func (m *mockCertStore) CountByManagedStatus(_ context.Context, _ *uuid.UUID) (int, int, error) {
	managed := 0
	for _, u := range m.certs {
		if u.ManagedStatus == "managed_in_vault" {
			managed++
		}
	}
	return managed, len(m.certs), nil
}

func TestReconcile_OneMatchOneShadow(t *testing.T) {
	t.Parallel()

	pemA, fpA := testCertWithCN(t, "cert-a.local")
	_, fpB := testCertWithCN(t, "cert-b.local")

	const serial = "01:aa:bb:cc"
	const mount = "pki/"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/mounts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				mount: map[string]interface{}{"type": "pki"},
			})
		case "/v1/pki/certs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{serial}},
			})
		case "/v1/pki/cert/" + serial:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"certificate":   pemA,
					"serial_number": serial,
					"issuer_id":     "issuer-abc",
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{Address: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}

	st := &mockCertStore{
		certs: map[string]store.ManagedStatusUpdate{
			fpA: {ManagedStatus: "unmanaged"},
			fpB: {ManagedStatus: "unmanaged"},
		},
	}

	reconciler := NewReconciler(client, st)
	summary, err := reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if summary.MountsScanned != 1 {
		t.Fatalf("mounts_scanned = %d, want 1", summary.MountsScanned)
	}
	if summary.VaultCertsRead != 1 {
		t.Fatalf("vault_certs_read = %d, want 1", summary.VaultCertsRead)
	}
	if summary.Matched != 1 {
		t.Fatalf("matched = %d, want 1", summary.Matched)
	}
	if summary.UnmatchedCLM != 1 {
		t.Fatalf("unmatched_clm = %d, want 1", summary.UnmatchedCLM)
	}

	gotA := st.certs[fpA]
	if gotA.ManagedStatus != "managed_in_vault" {
		t.Fatalf("cert A managed_status = %q, want managed_in_vault", gotA.ManagedStatus)
	}
	if gotA.VaultPKIMount != mount {
		t.Fatalf("cert A vault_pki_mount = %q, want %q", gotA.VaultPKIMount, mount)
	}
	if gotA.SerialNumber != serial {
		t.Fatalf("cert A serial_number = %q, want %q", gotA.SerialNumber, serial)
	}
	if gotA.VaultIssuerRef == nil || *gotA.VaultIssuerRef != "issuer-abc" {
		t.Fatalf("cert A vault_issuer_ref = %#v, want issuer-abc", gotA.VaultIssuerRef)
	}

	gotB := st.certs[fpB]
	if gotB.ManagedStatus != "unmanaged" {
		t.Fatalf("cert B should remain unmanaged, got %q", gotB.ManagedStatus)
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	t.Parallel()

	pemA, fpA := testCertWithCN(t, "idempotent.local")
	const serial = "02:cc:dd:ee"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/mounts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"pki/": map[string]interface{}{"type": "pki"},
			})
		case "/v1/pki/certs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{"keys": []string{serial}},
			})
		case "/v1/pki/cert/" + serial:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"certificate":   pemA,
					"serial_number": serial,
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	st := &mockCertStore{
		certs: map[string]store.ManagedStatusUpdate{
			fpA: {ManagedStatus: "unmanaged"},
		},
	}

	reconciler := NewReconciler(client, st)
	for i := 0; i < 2; i++ {
		summary, err := reconciler.Reconcile(context.Background())
		if err != nil {
			t.Fatalf("run %d: Reconcile: %v", i, err)
		}
		if summary.Matched != 1 {
			t.Fatalf("run %d: matched = %d, want 1", i, summary.Matched)
		}
	}
}

func TestReconcile_AllMountsFail_StatusFailed(t *testing.T) {
	t.Parallel()

	// Mount discovery succeeds, but every mount's cert-list returns an error and
	// nothing is read. This must NOT look like a successful "0 matched" run.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/mounts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"pki/": map[string]interface{}{"type": "pki"},
			})
		case "/v1/pki/certs":
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"unsupported operation"}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{Address: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}

	reconciler := NewReconciler(client, &mockCertStore{})
	summary, err := reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if summary.VaultCertsRead != 0 {
		t.Fatalf("vault_certs_read = %d, want 0", summary.VaultCertsRead)
	}
	if len(summary.Errors) == 0 {
		t.Fatal("expected per-mount errors to be recorded")
	}
	if summary.Status != "failed" {
		t.Fatalf("status = %q, want failed when nothing could be read", summary.Status)
	}
}

func TestReconcile_NoErrors_StatusOK(t *testing.T) {
	t.Parallel()

	pemA, fpA := testCertWithCN(t, "ok.local")
	const serial = "03:aa:bb:cc"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/mounts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"pki/": map[string]interface{}{"type": "pki"}})
		case "/v1/pki/certs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"keys": []string{serial}}})
		case "/v1/pki/cert/" + serial:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"certificate": pemA, "serial_number": serial}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	st := &mockCertStore{certs: map[string]store.ManagedStatusUpdate{fpA: {ManagedStatus: "unmanaged"}}}

	summary, err := NewReconciler(client, st).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if summary.Status != "ok" {
		t.Fatalf("status = %q, want ok", summary.Status)
	}
}

func testCertWithCN(t *testing.T, cn string) (string, string) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     []string{cn},
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	fp, err := FingerprintSHA256FromPEM(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	return pemStr, fp
}
