package report

import (
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func cert(status string, days int, scope, managed, issuer string, isCA bool, chain string) store.Certificate {
	c := store.Certificate{
		Status:          status,
		DaysUntilExpiry: days,
		CertScope:       scope,
		ManagedStatus:   managed,
		IssuerDN:        issuer,
		IsCA:            isCA,
		ChainStatus:     chain,
	}
	return c
}

func sampleCerts() []store.Certificate {
	return []store.Certificate{
		cert("valid", 200, "internal", "managed_in_vault", "CN=Vault Int", false, "complete"),
		cert("expiring_soon", 20, "internal", "unmanaged", "CN=Vault Int", false, "complete"),
		cert("expiring_soon", 5, "external", "unmanaged", "CN=Public CA", false, "complete"),
		cert("expired", -3, "external", "unmanaged", "CN=Public CA", false, "incomplete"),
	}
}

func TestBuildCertHealth(t *testing.T) {
	t.Parallel()

	h := BuildCertHealth(sampleCerts())
	if h.Total != 4 {
		t.Fatalf("total = %d, want 4", h.Total)
	}
	if h.ByStatus["expiring_soon"] != 2 {
		t.Fatalf("expiring_soon = %d, want 2", h.ByStatus["expiring_soon"])
	}
	if h.ExpiryBuckets.Expired != 1 {
		t.Fatalf("expired bucket = %d, want 1", h.ExpiryBuckets.Expired)
	}
	if h.ExpiryBuckets.Within7 != 1 {
		t.Fatalf("within7 = %d, want 1 (the 5-day cert)", h.ExpiryBuckets.Within7)
	}
	if h.ExpiryBuckets.Within30 != 1 {
		t.Fatalf("within30 = %d, want 1 (the 20-day cert)", h.ExpiryBuckets.Within30)
	}
	if h.ExpiryBuckets.Beyond90 != 1 {
		t.Fatalf("beyond90 = %d, want 1 (the 200-day cert)", h.ExpiryBuckets.Beyond90)
	}
}

func TestBuildExpiryRisk_Cumulative(t *testing.T) {
	t.Parallel()

	r := BuildExpiryRisk(sampleCerts())
	// 5-day and 20-day are within 30; only 5-day within 7; expired excluded.
	if r.Within7 != 1 {
		t.Fatalf("within7 = %d, want 1", r.Within7)
	}
	if r.Within30 != 2 {
		t.Fatalf("within30 = %d, want 2 (cumulative includes within7)", r.Within30)
	}
	if r.Within90 != 2 {
		t.Fatalf("within90 = %d, want 2", r.Within90)
	}
	if r.ByScope["external"].Within7 != 1 {
		t.Fatalf("external within7 = %d, want 1", r.ByScope["external"].Within7)
	}
	if r.ByScope["internal"].Within30 != 1 {
		t.Fatalf("internal within30 = %d, want 1", r.ByScope["internal"].Within30)
	}
}

func TestBuildIssuerTrust(t *testing.T) {
	t.Parallel()

	certs := []store.Certificate{
		// Internal CA, unmanaged => import candidate.
		cert("valid", 300, "internal", "unmanaged", "CN=Internal Root", true, "complete"),
		// Public CA leaves, unmanaged, NOT CA => not import candidates.
		cert("valid", 100, "external", "unmanaged", "CN=Public CA", false, "complete"),
		cert("valid", 90, "external", "unmanaged", "CN=Public CA", false, "complete"),
	}

	tr := BuildIssuerTrust(certs)
	get := func(dn string) *IssuerSummary {
		for i := range tr.Issuers {
			if tr.Issuers[i].IssuerDN == dn {
				return &tr.Issuers[i]
			}
		}
		return nil
	}

	publicCA := get("CN=Public CA")
	if publicCA == nil {
		t.Fatal("expected CN=Public CA issuer summary")
	}
	if publicCA.CertCount != 2 {
		t.Fatalf("public CA cert count = %d, want 2", publicCA.CertCount)
	}
	if publicCA.ImportCandidate {
		t.Fatal("public CA (leaf, no CA cert) must NOT be an import candidate")
	}

	internalRoot := get("CN=Internal Root")
	if internalRoot == nil || !internalRoot.ImportCandidate {
		t.Fatalf("internal CA (unmanaged, is_ca) should be an import candidate: %+v", internalRoot)
	}

	// Sorted by cert count desc: first issuer has >= second's count.
	if len(tr.Issuers) == 2 && tr.Issuers[0].CertCount < tr.Issuers[1].CertCount {
		t.Fatalf("issuers not sorted by cert count desc: %+v", tr.Issuers)
	}
}

func TestBuildScopeGovernance(t *testing.T) {
	t.Parallel()

	g := BuildScopeGovernance(sampleCerts())
	if g.ByScope["external"] != 2 || g.ByScope["internal"] != 2 {
		t.Fatalf("by_scope = %+v, want internal=2 external=2", g.ByScope)
	}
	if g.ByManagedStatus["unmanaged"] != 3 {
		t.Fatalf("unmanaged = %d, want 3", g.ByManagedStatus["unmanaged"])
	}
	if g.OwnerCoverage.Total != 4 || g.OwnerCoverage.WithOwner != 0 {
		t.Fatalf("owner coverage = %+v, want total=4 withOwner=0", g.OwnerCoverage)
	}
}

func TestBuildRecommendations(t *testing.T) {
	t.Parallel()

	insights := ClassifyAll(sampleCerts())
	recs := BuildRecommendations(insights)
	if len(recs) == 0 {
		t.Fatal("expected recommendations")
	}
	// Phases must be ordered (Discover < Choose < Import < Manage by rank).
	rankOf := map[string]int{"Discover": 0, "Choose": 1, "Import": 2, "Manage": 3}
	for i := 1; i < len(recs); i++ {
		if rankOf[recs[i-1].Phase] > rankOf[recs[i].Phase] {
			t.Fatalf("recommendations not phase-ordered: %+v", recs)
		}
	}
}
