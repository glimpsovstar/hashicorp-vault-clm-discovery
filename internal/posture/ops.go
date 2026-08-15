package posture

import (
	"fmt"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/report"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// EvaluateOps converts operational classifiers (report.ClassifyCertificate) into
// pack=ops findings. Overlaps with SC-081 expiry are skipped when sc081Already
// reports a non-info expiry finding for the same cert.
func EvaluateOps(cert store.Certificate, sc081 []compliance.Finding) []compliance.Finding {
	insights := report.ClassifyCertificate(cert)
	skipExpiry := hasSC081ExpiryViolation(sc081)

	var out []compliance.Finding
	for _, in := range insights {
		ruleID := opsRuleID(in)
		if ruleID == "" {
			continue
		}
		if skipExpiry && (in.Type == "expired" || in.Type == "expiring_soon") {
			continue
		}
		out = append(out, compliance.Finding{
			RuleID:      ruleID,
			Pack:        "ops",
			Severity:    string(in.Severity),
			Title:       opsTitle(in),
			Detail:      in.Description,
			CertID:      cert.ID,
			Fingerprint: cert.FingerprintSHA256,
			SubjectCN:   subjectCN(cert),
		})
	}
	return out
}

func hasSC081ExpiryViolation(findings []compliance.Finding) bool {
	for _, f := range findings {
		if f.Pack != "sc081" || f.Severity == "info" {
			continue
		}
		switch f.RuleID {
		case "sc081.expiry.expired", "sc081.expiry.critical", "sc081.expiry.warning":
			return true
		}
	}
	return false
}

func opsRuleID(in report.Insight) string {
	switch in.Type {
	case "expired":
		return "ops.expired"
	case "revoked":
		return "ops.revoked"
	case "expiring_soon":
		return "ops.expiring_soon"
	case "incomplete_chain":
		return "ops.incomplete_chain"
	case "untrusted_root":
		return "ops.untrusted_root"
	case "san_mismatch":
		return "ops.san_mismatch"
	case "weak_key":
		return "ops.weak_key"
	case "shadow_external":
		return "ops.shadow_external"
	case "shadow_internal":
		return "ops.shadow_internal"
	default:
		if in.Type == "" {
			return ""
		}
		return "ops." + in.Type
	}
}

func opsTitle(in report.Insight) string {
	switch in.Type {
	case "expired":
		return "Certificate expired on the wire"
	case "revoked":
		return "Revoked certificate still served"
	case "expiring_soon":
		return "Certificate expiring soon"
	case "incomplete_chain":
		return "Incomplete certificate chain"
	case "untrusted_root":
		return "Untrusted root"
	case "san_mismatch":
		return "Hostname / SAN mismatch"
	case "weak_key":
		return "Weak key"
	case "shadow_external":
		return "External shadow certificate"
	case "shadow_internal":
		return "Internal shadow certificate"
	default:
		return fmt.Sprintf("Operational finding (%s)", in.Type)
	}
}

func subjectCN(c store.Certificate) string {
	if c.SubjectCN != nil {
		return *c.SubjectCN
	}
	return ""
}

// EvaluateCertAll runs compliance packs plus ops (pack severities still unmapped).
func EvaluateCertAll(cert store.Certificate) []compliance.Finding {
	input := compliance.CertInputFromStore(cert)
	sc081 := compliance.EvaluateSC081(input)
	var findings []compliance.Finding
	findings = append(findings, sc081...)
	findings = append(findings, compliance.EvaluatePCI(input)...)
	findings = append(findings, compliance.EvaluateCrypto(input)...)
	findings = append(findings, EvaluateOps(cert, sc081)...)
	return findings
}
