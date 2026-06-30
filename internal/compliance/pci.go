package compliance

import (
	"fmt"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
)

// EvaluatePCI returns PCI 4.2.1.1 baseline inventory findings for a certificate.
func EvaluatePCI(cert CertInput) []Finding {
	var findings []Finding

	if cert.CertScope == governance.ScopeExternal && isMissingOwner(cert.Owner) {
		findings = append(findings, Finding{
			RuleID:      "pci.inventory.missing_owner",
			Pack:        "pci",
			Severity:    "warning",
			Title:       "External certificate missing owner",
			Detail:      "PCI inventory requires an owner for externally scoped certificates",
			CertID:      cert.ID,
			Fingerprint: cert.Fingerprint,
			SubjectCN:   cert.SubjectCN,
		})
	}

	if isProd(cert.Environment) && (isMissingOwner(cert.Owner) || len(cert.Tags) == 0) {
		findings = append(findings, Finding{
			RuleID:      "pci.inventory.untagged_prod",
			Pack:        "pci",
			Severity:    "warning",
			Title:       "Production certificate missing inventory metadata",
			Detail:      "Production certificates require owner and tags for PCI inventory completeness",
			CertID:      cert.ID,
			Fingerprint: cert.Fingerprint,
			SubjectCN:   cert.SubjectCN,
		})
	}

	if cert.ManagedStatus == "unmanaged" &&
		cert.CertScope == governance.ScopeExternal &&
		isProd(cert.Environment) {
		findings = append(findings, Finding{
			RuleID:      "pci.inventory.not_in_vault",
			Pack:        "pci",
			Severity:    "info",
			Title:       "External production certificate not in Vault",
			Detail:      fmt.Sprintf("Certificate %s is unmanaged and not correlated to Vault PKI", cert.Fingerprint),
			CertID:      cert.ID,
			Fingerprint: cert.Fingerprint,
			SubjectCN:   cert.SubjectCN,
		})
	}

	return findings
}

func isMissingOwner(owner *string) bool {
	return owner == nil || *owner == ""
}
