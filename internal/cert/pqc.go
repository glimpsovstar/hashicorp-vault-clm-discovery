package cert

import (
	"crypto/x509"
	"strings"
)

// PQCTag is a cheap inventory classification of the public key / signature.
// No PQ issuance — tag only.
type PQCTag string

const (
	PQCTagClassic PQCTag = "classic"
	PQCTagHybrid  PQCTag = "hybrid"
	PQCTagPQC     PQCTag = "pqc"
	PQCTagUnknown PQCTag = "unknown"
)

// ClassifyPQCTag inspects key type and signature algorithm strings (and optionally
// the parsed cert) to produce classic|hybrid|pqc|unknown.
func ClassifyPQCTag(keyType, signatureAlgorithm string, c *x509.Certificate) PQCTag {
	kt := strings.ToLower(strings.TrimSpace(keyType))
	sig := strings.ToLower(strings.TrimSpace(signatureAlgorithm))
	combined := kt + " " + sig

	if looksHybrid(combined) {
		return PQCTagHybrid
	}
	if looksPQC(combined) {
		return PQCTagPQC
	}
	switch kt {
	case "rsa", "ecdsa", "ed25519":
		return PQCTagClassic
	case "unknown", "":
		if c != nil && c.PublicKey != nil {
			// Parsed but unrecognized algorithm family.
			return PQCTagUnknown
		}
		return PQCTagUnknown
	default:
		if looksPQC(kt) {
			return PQCTagPQC
		}
		return PQCTagUnknown
	}
}

func looksPQC(s string) bool {
	markers := []string{
		"ml-dsa", "mldsa", "dilithium",
		"slh-dsa", "slhdsa", "sphincs",
		"ml-kem", "mlkem", "kyber",
		"falcon", "bike", "hqc",
	}
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func looksHybrid(s string) bool {
	if !(strings.Contains(s, "hybrid") || strings.Contains(s, "composite") || strings.Contains(s, "+")) {
		return false
	}
	hasClassic := strings.Contains(s, "rsa") || strings.Contains(s, "ecdsa") ||
		strings.Contains(s, "ed25519") || strings.Contains(s, "p256") ||
		strings.Contains(s, "p384") || strings.Contains(s, "x25519")
	return hasClassic && looksPQC(s)
}
