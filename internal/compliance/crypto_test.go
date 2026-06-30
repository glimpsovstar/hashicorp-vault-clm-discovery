package compliance

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEvaluateCrypto_WeakRSA(t *testing.T) {
	t.Parallel()

	cert := CertInput{
		ID:          uuid.New(),
		Fingerprint: "fp-rsa",
		SubjectCN:   "legacy.example.com",
		KeyType:     "RSA",
		KeyBits:     1024,
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	findings := EvaluateCrypto(cert)
	if !contains(ruleIDs(findings), "crypto.rsa.weak_key") {
		t.Fatalf("missing weak RSA finding: %+v", findings)
	}
	for _, f := range findings {
		if f.RuleID == "crypto.rsa.weak_key" && f.Severity != "critical" {
			t.Fatalf("severity = %q, want critical", f.Severity)
		}
	}
}

func TestEvaluateCrypto_SHA1Signature(t *testing.T) {
	t.Parallel()

	cert := CertInput{
		ID:                 uuid.New(),
		Fingerprint:        "fp-sha1",
		SubjectCN:          "old.example.com",
		KeyType:            "RSA",
		KeyBits:            2048,
		SignatureAlgorithm: "SHA1-RSA",
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	findings := EvaluateCrypto(cert)
	if !contains(ruleIDs(findings), "crypto.signature.sha1") {
		t.Fatalf("missing SHA-1 finding: %+v", findings)
	}
}

func TestEvaluateCrypto_WeakECDSA(t *testing.T) {
	t.Parallel()

	cert := CertInput{
		ID:          uuid.New(),
		Fingerprint: "fp-ec",
		SubjectCN:   "ec.example.com",
		KeyType:     "ECDSA",
		KeyBits:     224,
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	findings := EvaluateCrypto(cert)
	if !contains(ruleIDs(findings), "crypto.key.ecdsa.weak") {
		t.Fatalf("missing weak ECDSA finding: %+v", findings)
	}
}

func TestEvaluateCrypto_StrongCertNoFindings(t *testing.T) {
	t.Parallel()

	cert := CertInput{
		ID:                 uuid.New(),
		Fingerprint:        "fp-ok",
		SubjectCN:          "good.example.com",
		KeyType:            "RSA",
		KeyBits:            2048,
		SignatureAlgorithm: "SHA256-RSA",
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	if len(EvaluateCrypto(cert)) != 0 {
		t.Fatalf("expected no crypto findings for strong cert")
	}
}
