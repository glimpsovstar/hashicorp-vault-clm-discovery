package report

import (
	"sort"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// CertHealth summarizes lifecycle status counts and expiry bucketing for a scan.
type CertHealth struct {
	Total         int            `json:"total"`
	ByStatus      map[string]int `json:"by_status"`
	ExpiryBuckets ExpiryBuckets  `json:"expiry_buckets"`
}

// ExpiryBuckets are mutually exclusive tiers by days until expiry.
type ExpiryBuckets struct {
	Expired  int `json:"expired"`
	Within7  int `json:"within_7d"`
	Within30 int `json:"within_30d"`
	Within90 int `json:"within_90d"`
	Beyond90 int `json:"beyond_90d"`
}

// ExpiryRisk reports cumulative near-term expiry counts and a cross-tab by scope.
// Within7 <= Within30 <= Within90 (cumulative thresholds), excluding expired.
type ExpiryRisk struct {
	Within7  int                     `json:"within_7d"`
	Within30 int                     `json:"within_30d"`
	Within90 int                     `json:"within_90d"`
	ByScope  map[string]ExpiryCounts `json:"by_scope"`
}

// ExpiryCounts is the cumulative expiry breakdown for a single scope.
type ExpiryCounts struct {
	Within7  int `json:"within_7d"`
	Within30 int `json:"within_30d"`
	Within90 int `json:"within_90d"`
}

// IssuerTrust groups scan certificates by issuer to show chain quality and
// Vault linkage. Derived from the scan's certs, not the global issuer table.
type IssuerTrust struct {
	Issuers []IssuerSummary `json:"issuers"`
}

// IssuerSummary is per-issuer trust and import-candidacy data.
type IssuerSummary struct {
	IssuerDN        string         `json:"issuer_dn"`
	CertCount       int            `json:"cert_count"`
	CACount         int            `json:"ca_count"`
	InVault         int            `json:"in_vault"`
	ChainStatus     map[string]int `json:"chain_status"`
	ImportCandidate bool           `json:"import_candidate"`
}

// ScopeGovernance summarizes scope, management state, and ownership coverage.
type ScopeGovernance struct {
	ByScope         map[string]int `json:"by_scope"`
	ByManagedStatus map[string]int `json:"by_managed_status"`
	OwnerCoverage   Coverage       `json:"owner_coverage"`
}

// Coverage counts how many rows carry a value out of the total.
type Coverage struct {
	WithOwner int `json:"with_owner"`
	Total     int `json:"total"`
}

// BuildCertHealth counts status and buckets certs by days until expiry.
func BuildCertHealth(certs []store.Certificate) CertHealth {
	h := CertHealth{Total: len(certs), ByStatus: map[string]int{}}
	for _, c := range certs {
		h.ByStatus[c.Status]++
		switch {
		case c.Status == "expired":
			h.ExpiryBuckets.Expired++
		case c.DaysUntilExpiry <= 7:
			h.ExpiryBuckets.Within7++
		case c.DaysUntilExpiry <= 30:
			h.ExpiryBuckets.Within30++
		case c.DaysUntilExpiry <= 90:
			h.ExpiryBuckets.Within90++
		default:
			h.ExpiryBuckets.Beyond90++
		}
	}
	return h
}

// BuildExpiryRisk computes cumulative near-term expiry counts overall and by
// scope. Expired certs (negative days / status) are excluded.
func BuildExpiryRisk(certs []store.Certificate) ExpiryRisk {
	r := ExpiryRisk{ByScope: map[string]ExpiryCounts{}}
	for _, c := range certs {
		if c.Status == "expired" || c.DaysUntilExpiry < 0 {
			continue
		}
		scope := c.CertScope
		ec := r.ByScope[scope]
		if c.DaysUntilExpiry <= 90 {
			r.Within90++
			ec.Within90++
		}
		if c.DaysUntilExpiry <= 30 {
			r.Within30++
			ec.Within30++
		}
		if c.DaysUntilExpiry <= 7 {
			r.Within7++
			ec.Within7++
		}
		r.ByScope[scope] = ec
	}
	return r
}

// BuildIssuerTrust groups certs by issuer DN, sorted by cert count desc then DN.
func BuildIssuerTrust(certs []store.Certificate) IssuerTrust {
	byDN := map[string]*IssuerSummary{}
	for _, c := range certs {
		s := byDN[c.IssuerDN]
		if s == nil {
			s = &IssuerSummary{IssuerDN: c.IssuerDN, ChainStatus: map[string]int{}}
			byDN[c.IssuerDN] = s
		}
		s.CertCount++
		if c.IsCA {
			s.CACount++
		}
		if c.ManagedStatus == "managed_in_vault" {
			s.InVault++
		}
		s.ChainStatus[c.ChainStatus]++
	}

	issuers := make([]IssuerSummary, 0, len(byDN))
	for _, s := range byDN {
		s.ImportCandidate = s.InVault == 0
		issuers = append(issuers, *s)
	}
	sort.SliceStable(issuers, func(i, j int) bool {
		if issuers[i].CertCount != issuers[j].CertCount {
			return issuers[i].CertCount > issuers[j].CertCount
		}
		return issuers[i].IssuerDN < issuers[j].IssuerDN
	})
	return IssuerTrust{Issuers: issuers}
}

// BuildScopeGovernance counts scope, managed status, and owner coverage.
func BuildScopeGovernance(certs []store.Certificate) ScopeGovernance {
	g := ScopeGovernance{ByScope: map[string]int{}, ByManagedStatus: map[string]int{}}
	g.OwnerCoverage.Total = len(certs)
	for _, c := range certs {
		g.ByScope[c.CertScope]++
		g.ByManagedStatus[c.ManagedStatus]++
		if c.Owner != nil && *c.Owner != "" {
			g.OwnerCoverage.WithOwner++
		}
	}
	return g
}

// Recommendation is a deduped, ranked action derived from insight codes.
type Recommendation struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
	Phase string `json:"phase"`
	Title string `json:"title"`
}

var recMeta = map[string]struct {
	phase string
	title string
	rank  int // lifecycle order for stable grouping
}{
	RecRescan:          {"Discover", "Import intermediates and rescan to complete chains", 0},
	RecMonitorExternal: {"Choose", "Track public-CA certificates in CLM only", 1},
	RecImportCA:        {"Import", "Import CA/issuer material into Vault PKI", 2},
	RecCatalogImport:   {"Import", "Catalog certificate in CLM without a Vault write", 2},
	RecReconcileVault:  {"Manage", "Run Vault PKI reconcile to match deployed certs", 3},
	RecPlanRenewal:     {"Manage", "Plan renewal/replacement for expiring or invalid certs", 3},
	RecFixSAN:          {"Manage", "Fix hostname/SAN mismatches", 3},
}

// BuildRecommendations dedups insight recommendation codes into a ranked list,
// grouped by lifecycle phase then by frequency.
func BuildRecommendations(insights []Insight) []Recommendation {
	counts := map[string]int{}
	for _, in := range insights {
		if in.Recommendation != "" {
			counts[in.Recommendation]++
		}
	}
	recs := make([]Recommendation, 0, len(counts))
	for code, n := range counts {
		m := recMeta[code]
		recs = append(recs, Recommendation{Code: code, Count: n, Phase: m.phase, Title: m.title})
	}
	sort.SliceStable(recs, func(i, j int) bool {
		ri, rj := recMeta[recs[i].Code].rank, recMeta[recs[j].Code].rank
		if ri != rj {
			return ri < rj
		}
		if recs[i].Count != recs[j].Count {
			return recs[i].Count > recs[j].Count
		}
		return recs[i].Code < recs[j].Code
	})
	return recs
}
