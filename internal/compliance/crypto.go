package compliance

import (
	"strings"
)

// EvaluateCrypto returns algorithm inventory findings for a certificate.
func EvaluateCrypto(cert CertInput) []Finding {
	var findings []Finding

	if strings.EqualFold(cert.KeyType, "RSA") && cert.KeyBits < 2048 {
		findings = append(findings, Finding{
			RuleID:      "crypto.rsa.weak_key",
			Pack:        "crypto",
			Severity:    "critical",
			Title:       "RSA key below 2048 bits",
			Detail:      "RSA keys must be at least 2048 bits",
			CertID:      cert.ID,
			Fingerprint: cert.Fingerprint,
			SubjectCN:   cert.SubjectCN,
		})
	}

	if containsSHA1(cert.SignatureAlgorithm) {
		findings = append(findings, Finding{
			RuleID:      "crypto.signature.sha1",
			Pack:        "crypto",
			Severity:    "critical",
			Title:       "SHA-1 signature algorithm",
			Detail:      "SHA-1 signed certificates are deprecated",
			CertID:      cert.ID,
			Fingerprint: cert.Fingerprint,
			SubjectCN:   cert.SubjectCN,
		})
	}

	if strings.EqualFold(cert.KeyType, "ECDSA") && cert.KeyBits < 256 {
		findings = append(findings, Finding{
			RuleID:      "crypto.key.ecdsa.weak",
			Pack:        "crypto",
			Severity:    "warning",
			Title:       "ECDSA key below 256 bits",
			Detail:      "ECDSA keys should be at least 256 bits",
			CertID:      cert.ID,
			Fingerprint: cert.Fingerprint,
			SubjectCN:   cert.SubjectCN,
		})
	}

	return findings
}

func containsSHA1(alg string) bool {
	upper := strings.ToUpper(alg)
	return strings.Contains(upper, "SHA1") || strings.Contains(upper, "SHA-1")
}
