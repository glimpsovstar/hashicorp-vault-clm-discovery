package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
)

// RenderMarkdown returns a human-readable scan report without full PEM bodies.
func RenderMarkdown(doc Document) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Executive summary\n\n")
	fmt.Fprintf(&b, "**Scan ID:** `%s`\n\n", doc.ScanID)
	fmt.Fprintf(&b, "**Status:** %s\n\n", doc.ScanStatus)
	fmt.Fprintf(&b, "**Generated:** %s\n\n", doc.GeneratedAt.Format(timeRFC3339))
	b.WriteString("**Scope:** ")
	b.WriteString(formatScope(doc.Scope))
	b.WriteString("\n\n")

	fmt.Fprintf(&b, "- **Certificates discovered:** %d\n", doc.BlindSpot.Discovered)
	fmt.Fprintf(&b, "- **Vault managed:** %d\n", doc.BlindSpot.VaultManaged)
	fmt.Fprintf(&b, "- **Shadow certs (on wire, not in Vault):** %d\n", doc.BlindSpot.Shadow)
	fmt.Fprintf(&b, "- **SC-081 violations:** %d\n", doc.BlindSpot.SC081Violations)
	fmt.Fprintf(&b, "- **PCI findings:** %d\n", doc.Compliance.PCIFindingCount)
	fmt.Fprintf(&b, "- **Total compliance findings:** %d\n\n", len(doc.Compliance.Findings))

	b.WriteString("## Blind-spot reveal\n\n")
	fmt.Fprintf(&b, "Vault sees **%d** managed certificate(s). The scan found **%d** unique certificate(s) on the wire. **%d** shadow certificate(s) are visible on the network but not matched to Vault PKI.\n\n", doc.BlindSpot.VaultManaged, doc.BlindSpot.Discovered, doc.BlindSpot.Shadow)
	if doc.BlindSpot.Shadow > 0 {
		b.WriteString("Shadow certs represent the Vault blind spot — TLS endpoints serving certificates that Vault PKI reconcile did not match.\n\n")
	} else {
		b.WriteString("No shadow certificates detected for this scan scope.\n\n")
	}

	b.WriteString("## SC-081 posture\n\n")
	fmt.Fprintf(&b, "**Violations:** %d (of %d certificates evaluated)\n\n", doc.Compliance.SC081ViolationCount, doc.Compliance.TotalCerts)
	writeFindingsByPack(&b, doc.Compliance, "sc081")

	b.WriteString("## PCI inventory gaps\n\n")
	fmt.Fprintf(&b, "**Findings:** %d\n\n", doc.Compliance.PCIFindingCount)
	writeFindingsByPack(&b, doc.Compliance, "pci")

	b.WriteString("## Algorithm inventory\n\n")
	inv := doc.Compliance.AlgorithmInventory
	fmt.Fprintf(&b, "| Algorithm | Count |\n|-----------|-------|\n")
	fmt.Fprintf(&b, "| RSA 2048+ | %d |\n", inv.RSA2048Plus)
	fmt.Fprintf(&b, "| RSA under 2048 | %d |\n", inv.RSAUnder2048)
	fmt.Fprintf(&b, "| ECDSA | %d |\n", inv.ECDSA)
	fmt.Fprintf(&b, "| Ed25519 | %d |\n", inv.Ed25519)
	fmt.Fprintf(&b, "| SHA-1 signatures | %d |\n\n", inv.SHA1Signatures)

	b.WriteString("## Scan diagnostics\n\n")
	d := doc.Diagnostics
	fmt.Fprintf(&b, "- **Targets:** %d succeeded / %d failed / %d total\n", d.TargetsSucceeded, d.TargetsFailed, d.TargetsTotal)
	fmt.Fprintf(&b, "- **Certificates persisted:** %d\n", d.CertsFound)
	fmt.Fprintf(&b, "- **Upsert failures:** %d\n", d.UpsertFailures)
	if d.Error != nil && *d.Error != "" {
		fmt.Fprintf(&b, "- **Scan error:** %s\n", *d.Error)
	}
	if len(d.ExpansionWarnings) > 0 {
		b.WriteString("\n**Expansion warnings:**\n\n")
		for _, w := range d.ExpansionWarnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	if len(d.FailureSamples) > 0 {
		b.WriteString("\n**Failure samples:**\n\n")
		b.WriteString("| Kind | Target | Reason |\n|------|--------|--------|\n")
		limit := len(d.FailureSamples)
		if limit > 10 {
			limit = 10
		}
		for _, s := range d.FailureSamples[:limit] {
			target := fmt.Sprintf("%s:%d", s.IP, s.Port)
			if s.Hostname != "" {
				target = s.Hostname + ":" + fmt.Sprint(s.Port)
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", escapeCell(s.Kind), escapeCell(target), escapeCell(s.Reason))
		}
	}
	b.WriteString("\n")

	writeCertHealth(&b, doc.CertHealth)
	writeExpiryRisk(&b, doc.ExpiryRisk)
	writeIssuerTrust(&b, doc.IssuerTrust)
	writeScopeGovernance(&b, doc.Governance)
	writeTopInsights(&b, doc.Insights)
	writeRecommendations(&b, doc.Recommends)

	return b.String()
}

func writeCertHealth(b *strings.Builder, h CertHealth) {
	b.WriteString("## Certificate health\n\n")
	fmt.Fprintf(b, "**Total certificates:** %d\n\n", h.Total)
	if len(h.ByStatus) > 0 {
		b.WriteString("| Status | Count |\n|--------|-------|\n")
		for _, k := range sortedKeys(h.ByStatus) {
			fmt.Fprintf(b, "| %s | %d |\n", escapeCell(k), h.ByStatus[k])
		}
		b.WriteString("\n")
	}
	e := h.ExpiryBuckets
	b.WriteString("**Days until expiry:**\n\n")
	b.WriteString("| Bucket | Count |\n|--------|-------|\n")
	fmt.Fprintf(b, "| Expired | %d |\n", e.Expired)
	fmt.Fprintf(b, "| ≤ 7 days | %d |\n", e.Within7)
	fmt.Fprintf(b, "| 8–30 days | %d |\n", e.Within30)
	fmt.Fprintf(b, "| 31–90 days | %d |\n", e.Within90)
	fmt.Fprintf(b, "| > 90 days | %d |\n\n", e.Beyond90)
}

func writeExpiryRisk(b *strings.Builder, r ExpiryRisk) {
	b.WriteString("## Expiry risk\n\n")
	fmt.Fprintf(b, "- **Expiring within 7 days:** %d\n", r.Within7)
	fmt.Fprintf(b, "- **Expiring within 30 days:** %d\n", r.Within30)
	fmt.Fprintf(b, "- **Expiring within 90 days:** %d\n\n", r.Within90)
	if len(r.ByScope) > 0 {
		b.WriteString("| Scope | ≤7d | ≤30d | ≤90d |\n|-------|-----|------|------|\n")
		for _, scope := range sortedKeys(mapKeysExpiry(r.ByScope)) {
			c := r.ByScope[scope]
			label := scope
			if label == "" {
				label = "—"
			}
			fmt.Fprintf(b, "| %s | %d | %d | %d |\n", escapeCell(label), c.Within7, c.Within30, c.Within90)
		}
		b.WriteString("\n")
	}
}

func writeIssuerTrust(b *strings.Builder, t IssuerTrust) {
	b.WriteString("## Issuer trust & chain quality\n\n")
	if len(t.Issuers) == 0 {
		b.WriteString("No issuers observed for this scan.\n\n")
		return
	}
	b.WriteString("| Issuer | Certs | CA | In Vault | Import candidate |\n|--------|-------|----|----------|------------------|\n")
	limit := len(t.Issuers)
	if limit > 25 {
		limit = 25
	}
	for _, s := range t.Issuers[:limit] {
		cand := "no"
		if s.ImportCandidate {
			cand = "yes"
		}
		fmt.Fprintf(b, "| %s | %d | %d | %d | %s |\n", escapeCell(s.IssuerDN), s.CertCount, s.CACount, s.InVault, cand)
	}
	b.WriteString("\n")
}

func writeScopeGovernance(b *strings.Builder, g ScopeGovernance) {
	b.WriteString("## Scope & governance\n\n")
	if len(g.ByScope) > 0 {
		b.WriteString("**By scope:**\n\n")
		for _, k := range sortedKeys(g.ByScope) {
			fmt.Fprintf(b, "- %s: %d\n", escapeCell(k), g.ByScope[k])
		}
		b.WriteString("\n")
	}
	if len(g.ByManagedStatus) > 0 {
		b.WriteString("**By managed status:**\n\n")
		for _, k := range sortedKeys(g.ByManagedStatus) {
			fmt.Fprintf(b, "- %s: %d\n", escapeCell(k), g.ByManagedStatus[k])
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "**Ownership coverage:** %d of %d certificates have an owner.\n\n", g.OwnerCoverage.WithOwner, g.OwnerCoverage.Total)
}

func writeTopInsights(b *strings.Builder, insights []Insight) {
	b.WriteString("## Insights\n\n")
	if len(insights) == 0 {
		b.WriteString("No insights for this scan.\n\n")
		return
	}
	b.WriteString("| Severity | Type | Subject | Recommendation | Description |\n|----------|------|---------|----------------|-------------|\n")
	limit := len(insights)
	if limit > 50 {
		limit = 50
	}
	for _, in := range insights[:limit] {
		subject := in.SubjectCN
		if subject == "" {
			subject = "—"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
			escapeCell(string(in.Severity)), escapeCell(in.Type), escapeCell(subject),
			escapeCell(in.Recommendation), escapeCell(in.Description))
	}
	b.WriteString("\n")
}

func writeRecommendations(b *strings.Builder, recs []Recommendation) {
	b.WriteString("## Recommendations\n\n")
	if len(recs) == 0 {
		b.WriteString("No recommended actions.\n\n")
		return
	}
	b.WriteString("| Phase | Action | Count |\n|-------|--------|-------|\n")
	for _, r := range recs {
		fmt.Fprintf(b, "| %s | %s | %d |\n", escapeCell(r.Phase), escapeCell(r.Title), r.Count)
	}
	b.WriteString("\n")
}

// sortedKeys returns the keys of a count map in stable ascending order.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mapKeysExpiry adapts an ExpiryCounts map to the []string sorting helper.
func mapKeysExpiry(m map[string]ExpiryCounts) map[string]int {
	out := make(map[string]int, len(m))
	for k := range m {
		out[k] = 0
	}
	return out
}

const timeRFC3339 = "2006-01-02 15:04:05 UTC"

// escapeCell neutralizes markdown-table metacharacters in values that may be
// attacker-influenced (e.g. a scanned endpoint's Subject CN). It escapes pipes
// so a value cannot open new columns, and collapses newlines so a value cannot
// break out of its row to inject headings or extra rows.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	// Escape backslashes before pipes: otherwise an input like `\|` would become
	// `\\|`, where GFM renders `\\` as a literal backslash and leaves the pipe
	// live as a column separator.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}

func formatScope(scope ScopeSummary) string {
	var parts []string
	if len(scope.Hostnames) > 0 {
		parts = append(parts, "hostnames: "+strings.Join(scope.Hostnames, ", "))
	}
	if len(scope.CIDRs) > 0 {
		parts = append(parts, "CIDRs: "+strings.Join(scope.CIDRs, ", "))
	}
	if len(scope.Ports) > 0 {
		portStrs := make([]string, len(scope.Ports))
		for i, p := range scope.Ports {
			portStrs[i] = fmt.Sprint(p)
		}
		parts = append(parts, "ports: "+strings.Join(portStrs, ", "))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

func writeFindingsByPack(b *strings.Builder, summary compliance.ComplianceSummary, pack string) {
	var findings []compliance.Finding
	for _, f := range summary.Findings {
		if f.Pack == pack {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		fmt.Fprintf(b, "No %s findings.\n\n", pack)
		return
	}
	b.WriteString("| Severity | Rule | Subject | Fingerprint |\n|----------|------|---------|-------------|\n")
	limit := len(findings)
	if limit > 20 {
		limit = 20
	}
	for _, f := range findings[:limit] {
		fp := f.Fingerprint
		if len(fp) > 12 {
			fp = fp[:12] + "…"
		}
		subject := f.SubjectCN
		if subject == "" {
			subject = "—"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", escapeCell(f.Severity), escapeCell(f.RuleID), escapeCell(subject), escapeCell(fp))
	}
	b.WriteString("\n")
}
