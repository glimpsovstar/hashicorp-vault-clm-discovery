package revocation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// leafSignedBy mints a leaf certificate signed by the given CA and returns the
// parsed cert plus its PEM.
func leafSignedBy(t *testing.T, ca testCA, serial *big.Int) (*x509.Certificate, string) {
	t.Helper()
	key := ca.key // reuse a key; the leaf's own key is irrelevant to OCSP status
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return leaf, pemStr
}

// ocspResponder serves a CA-signed OCSP response with the given status for leaf.
func ocspResponder(t *testing.T, ca testCA, leaf *x509.Certificate, status int) *httptest.Server {
	t.Helper()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = time.Now().Add(-time.Minute)
		tmpl.RevocationReason = ocsp.Unspecified
	}
	respDER, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(respDER)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckOCSP_GoodVerified(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	leaf, leafPEM := leafSignedBy(t, ca, big.NewInt(0x77))
	srv := ocspResponder(t, ca, leaf, ocsp.Good)

	res, err := CheckOCSP(context.Background(), srv.Client(), leafPEM, ca.certPEM, []string{srv.URL})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if res.Status != StatusGood {
		t.Fatalf("status = %q, want good", res.Status)
	}
	if !res.Verified {
		t.Fatal("OCSP response should be verified against issuer")
	}
}

func TestCheckOCSP_Revoked(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	leaf, leafPEM := leafSignedBy(t, ca, big.NewInt(0x78))
	srv := ocspResponder(t, ca, leaf, ocsp.Revoked)

	res, err := CheckOCSP(context.Background(), srv.Client(), leafPEM, ca.certPEM, []string{srv.URL})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if res.Status != StatusRevoked {
		t.Fatalf("status = %q, want revoked", res.Status)
	}
	if !res.Verified || res.RevokedAt == nil {
		t.Fatalf("expected verified revoked with RevokedAt: %+v", res)
	}
}

func TestCheckOCSP_UnknownWhenNoResponderOrIssuer(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	_, leafPEM := leafSignedBy(t, ca, big.NewInt(0x79))

	// No OCSP servers.
	res, _ := CheckOCSP(context.Background(), http.DefaultClient, leafPEM, ca.certPEM, nil)
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown (no responder)", res.Status)
	}
	// No issuer.
	res, _ = CheckOCSP(context.Background(), http.DefaultClient, leafPEM, "", []string{"http://x"})
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown (no issuer)", res.Status)
	}
}

func TestCheck_PrefersOCSPThenCRL(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	leaf, leafPEM := leafSignedBy(t, ca, big.NewInt(0x7a))
	ocspSrv := ocspResponder(t, ca, leaf, ocsp.Revoked)

	// OCSP says revoked; CRL is empty. Combined Check must return the OCSP result.
	res, err := Check(context.Background(), ocspSrv.Client(), CheckInput{
		SerialHex:   leaf.SerialNumber.Text(16),
		LeafPEM:     leafPEM,
		IssuerPEM:   ca.certPEM,
		OCSPServers: []string{ocspSrv.URL},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Status != StatusRevoked || res.Source != "ocsp" {
		t.Fatalf("expected ocsp revoked, got %+v", res)
	}
}

func TestCheck_FallsBackToCRL(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	serial := big.NewInt(0x7b)
	crlSrv := crlServer(t, ca, serial)

	// No OCSP servers -> OCSP unknown -> fall back to CRL (which revokes serial).
	res, err := Check(context.Background(), crlSrv.Client(), CheckInput{
		SerialHex: serial.Text(16),
		IssuerPEM: ca.certPEM,
		CRLURLs:   []string{crlSrv.URL},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Status != StatusRevoked || res.Source != "crl" {
		t.Fatalf("expected crl revoked, got %+v", res)
	}
}
