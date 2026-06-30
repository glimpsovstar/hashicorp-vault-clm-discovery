package compliance

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
)

func TestEvaluatePCI_MissingOwner(t *testing.T) {
	t.Parallel()

	cert := CertInput{
		ID:        uuid.New(),
		Fingerprint: "fp1",
		SubjectCN: "api.example.com",
		CertScope: governance.ScopeExternal,
		Owner:     nil,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	findings := EvaluatePCI(cert)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "pci.inventory.missing_owner" {
		t.Fatalf("rule = %q", findings[0].RuleID)
	}
	if findings[0].Severity != "warning" {
		t.Fatalf("severity = %q, want warning", findings[0].Severity)
	}
}

func TestEvaluatePCI_UntaggedProd(t *testing.T) {
	t.Parallel()

	env := "prod"
	cert := CertInput{
		ID:          uuid.New(),
		Fingerprint: "fp2",
		SubjectCN:   "app.example.com",
		Environment: &env,
		Owner:       nil,
		Tags:        nil,
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	findings := EvaluatePCI(cert)
	rules := ruleIDs(findings)
	if !contains(rules, "pci.inventory.untagged_prod") {
		t.Fatalf("missing untagged_prod in %+v", findings)
	}
}

func TestEvaluatePCI_NotInVault(t *testing.T) {
	t.Parallel()

	env := "prod"
	cert := CertInput{
		ID:            uuid.New(),
		Fingerprint:   "fp3",
		SubjectCN:     "shop.example.com",
		CertScope:     governance.ScopeExternal,
		Environment:   &env,
		ManagedStatus: "unmanaged",
		Owner:         strPtr("team-a"),
		Tags:          []string{"pci"},
		NotBefore:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	findings := EvaluatePCI(cert)
	if !contains(ruleIDs(findings), "pci.inventory.not_in_vault") {
		t.Fatalf("missing not_in_vault in %+v", findings)
	}
}

func TestEvaluatePCI_NoFindingsWhenComplete(t *testing.T) {
	t.Parallel()

	env := "prod"
	cert := CertInput{
		ID:            uuid.New(),
		Fingerprint:   "fp4",
		SubjectCN:     "secure.example.com",
		CertScope:     governance.ScopeInternal,
		Environment:   &env,
		ManagedStatus: "managed_in_vault",
		Owner:         strPtr("platform"),
		Tags:          []string{"app:payments"},
		NotBefore:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}

	if len(EvaluatePCI(cert)) != 0 {
		t.Fatalf("expected no PCI findings for complete internal cert")
	}
}

func ruleIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
