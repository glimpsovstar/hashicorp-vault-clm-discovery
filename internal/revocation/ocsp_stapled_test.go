package revocation

import (
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestParseStapledOCSP_RevokedVerified(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	leaf, leafPEM := leafSignedBy(t, ca, big.NewInt(0x91))

	tmpl := ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     leaf.SerialNumber,
		ThisUpdate:       time.Now().Add(-time.Minute),
		NextUpdate:       time.Now().Add(time.Hour),
		RevokedAt:        time.Now().Add(-time.Minute),
		RevocationReason: ocsp.KeyCompromise,
	}
	staple, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}

	res, err := ParseStapledOCSP(staple, leafPEM, ca.certPEM)
	if err != nil {
		t.Fatalf("ParseStapledOCSP: %v", err)
	}
	if res.Status != StatusRevoked {
		t.Fatalf("status = %q, want revoked", res.Status)
	}
	if !res.Verified || res.RevokedAt == nil {
		t.Fatalf("expected verified revoked with RevokedAt: %+v", res)
	}
	if res.Source != "ocsp_stapled" {
		t.Fatalf("source = %q, want ocsp_stapled", res.Source)
	}
}

func TestParseStapledOCSP_GoodVerified(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	leaf, leafPEM := leafSignedBy(t, ca, big.NewInt(0x92))

	tmpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	staple, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}

	res, err := ParseStapledOCSP(staple, leafPEM, ca.certPEM)
	if err != nil {
		t.Fatalf("ParseStapledOCSP: %v", err)
	}
	if res.Status != StatusGood || !res.Verified {
		t.Fatalf("expected verified good, got %+v", res)
	}
}

func TestParseStapledOCSP_WrongIssuerNotVerified(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	other := newTestCA(t)
	leaf, leafPEM := leafSignedBy(t, ca, big.NewInt(0x93))

	tmpl := ocsp.Response{
		Status:       ocsp.Revoked,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
		RevokedAt:    time.Now().Add(-time.Minute),
	}
	staple, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}

	// Verified against the wrong issuer must fail closed: unknown + unverified.
	res, err := ParseStapledOCSP(staple, leafPEM, other.certPEM)
	if err != nil {
		t.Fatalf("ParseStapledOCSP: %v", err)
	}
	if res.Status != StatusUnknown || res.Verified {
		t.Fatalf("expected unknown+unverified for wrong issuer, got %+v", res)
	}
}

func TestParseStapledOCSP_EmptyOrMissingInputs(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t)
	_, leafPEM := leafSignedBy(t, ca, big.NewInt(0x94))

	cases := []struct {
		name      string
		staple    []byte
		leafPEM   string
		issuerPEM string
	}{
		{"no staple", nil, leafPEM, ca.certPEM},
		{"no leaf", []byte{0x01}, "", ca.certPEM},
		{"no issuer", []byte{0x01}, leafPEM, ""},
		{"garbage staple", []byte{0x01, 0x02, 0x03}, leafPEM, ca.certPEM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseStapledOCSP(tc.staple, tc.leafPEM, tc.issuerPEM)
			if err != nil {
				t.Fatalf("ParseStapledOCSP: %v", err)
			}
			if res.Status != StatusUnknown || res.Verified {
				t.Fatalf("expected unknown+unverified, got %+v", res)
			}
		})
	}
}
