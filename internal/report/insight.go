package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// Severity ranks an insight from informational to critical, matching the
// reporting-architecture.md severity table.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Recommendation codes are the fixed lifecycle actions from
// reporting-architecture.md; renderers and automation key off these.
const (
	RecMonitorExternal = "monitor_external"
	RecReconcileVault  = "reconcile_vault"
	RecImportCA        = "import_ca"
	RecCatalogImport   = "catalog_import"
	RecFixSAN          = "fix_san"
	RecRescan          = "rescan"
	RecPlanRenewal     = "plan_renewal"
)

// Insight is one atomic finding for a certificate, issuer, or scan-level signal.
// It is the CLM analogue of a Vault Radar "risk" but scoped to TLS deployment
// inventory — never secrets or PII.
type Insight struct {
	Category       string            `json:"category"`
	Type           string            `json:"type"`
	Severity       Severity          `json:"severity"`
	Recommendation string            `json:"recommendation"`
	SubjectCN      string            `json:"subject_cn,omitempty"`
	Fingerprint    string            `json:"fingerprint_sha256,omitempty"`
	IssuerDN       string            `json:"issuer_dn,omitempty"`
	Description    string            `json:"description"`
	Tags           []string          `json:"tags,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ClassifyCertificate derives zero or more insights for a single certificate.
// A healthy, Vault-managed, chain-complete cert that matches its SAN yields no
// insights. Conditions are independent, so a cert can surface several.
func ClassifyCertificate(c store.Certificate) []Insight {
	cn := ""
	if c.SubjectCN != nil {
		cn = *c.SubjectCN
	}
	base := func() Insight {
		return Insight{SubjectCN: cn, Fingerprint: c.FingerprintSHA256, IssuerDN: c.IssuerDN, Tags: certTags(c)}
	}
	var out []Insight

	switch c.Status {
	case "expired":
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "certificate", "expired", SeverityHigh, RecPlanRenewal
		i.Description = "Certificate has expired but is still served on the wire"
		out = append(out, i)
	case "revoked":
		// A revoked cert still being served is the strongest deployment signal.
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "certificate", "revoked", SeverityCritical, RecPlanRenewal
		i.Description = "Certificate is revoked in Vault but still served on the wire"
		out = append(out, i)
	case "expiring_soon":
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "certificate", "expiring_soon", SeverityMedium, RecPlanRenewal
		i.Description = fmt.Sprintf("Certificate expires in %d day(s)", c.DaysUntilExpiry)
		i.Metadata = map[string]string{"days_until_expiry": strconv.Itoa(c.DaysUntilExpiry)}
		out = append(out, i)
	}

	switch c.ChainStatus {
	case "incomplete":
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "issuer", "incomplete_chain", SeverityMedium, RecRescan
		i.Description = "Presented chain is incomplete; import the intermediate and rescan"
		out = append(out, i)
	case "untrusted_root":
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "issuer", "untrusted_root", SeverityMedium, RecImportCA
		i.Description = "Chain terminates in an untrusted root"
		out = append(out, i)
	}

	if !c.HostnameMatchesSAN {
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "certificate", "san_mismatch", SeverityLow, RecFixSAN
		i.Description = "Observed hostname does not match certificate SANs"
		out = append(out, i)
	}

	if isWeakKey(c) {
		i := base()
		i.Category, i.Type, i.Severity, i.Recommendation = "certificate", "weak_key", SeverityHigh, RecPlanRenewal
		i.Description = fmt.Sprintf("Weak key: %s %d-bit", c.KeyType, c.KeyBits)
		out = append(out, i)
	}

	if c.ManagedStatus == "unmanaged" {
		i := base()
		if c.CertScope == "external" {
			i.Category, i.Type, i.Severity, i.Recommendation = "governance", "shadow_external", SeverityInfo, RecMonitorExternal
			i.Description = "External (public CA) certificate not managed by Vault"
		} else {
			i.Category, i.Type, i.Severity, i.Recommendation = "governance", "shadow_internal", SeverityLow, RecReconcileVault
			i.Description = "Internal certificate on the wire but not matched to Vault PKI"
		}
		out = append(out, i)
	}

	return out
}

// ClassifyAll flattens insights across a scan's certificates, sorted for stable
// rendering (severity desc, then subject CN, then type).
func ClassifyAll(certs []store.Certificate) []Insight {
	var all []Insight
	for _, c := range certs {
		all = append(all, ClassifyCertificate(c)...)
	}
	SortInsights(all)
	return all
}

// SortInsights orders insights by severity (highest first), then subject CN and
// type, so output is deterministic across runs.
func SortInsights(in []Insight) {
	sort.SliceStable(in, func(i, j int) bool {
		ri, rj := severityRank(in[i].Severity), severityRank(in[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if in[i].SubjectCN != in[j].SubjectCN {
			return in[i].SubjectCN < in[j].SubjectCN
		}
		return in[i].Type < in[j].Type
	})
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// isWeakKey flags RSA keys below the 2048-bit floor. ECDSA/Ed25519 sizes are not
// compared here; broader crypto posture lives in the compliance evaluator.
func isWeakKey(c store.Certificate) bool {
	return strings.EqualFold(c.KeyType, "RSA") && c.KeyBits > 0 && c.KeyBits < 2048
}

func certTags(c store.Certificate) []string {
	var tags []string
	if c.CertScope != "" {
		tags = append(tags, c.CertScope)
	}
	if c.ManagedStatus != "" {
		tags = append(tags, c.ManagedStatus)
	}
	return tags
}
