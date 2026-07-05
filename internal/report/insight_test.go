package report

import (
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func strptr(s string) *string { return &s }

// baseCert is a healthy, Vault-managed, chain-complete cert that should yield
// no insights; tests override individual fields to trigger each classifier rule.
func baseCert() store.Certificate {
	return store.Certificate{
		SubjectCN:          strptr("app.example.com"),
		FingerprintSHA256:  "abc123",
		IssuerDN:           "CN=Vault Intermediate",
		Status:             "valid",
		DaysUntilExpiry:    120,
		ChainStatus:        "complete",
		HostnameMatchesSAN: true,
		KeyType:            "RSA",
		KeyBits:            2048,
		ManagedStatus:      "managed_in_vault",
		CertScope:          "internal",
	}
}

func hasInsight(insights []Insight, typ string) (Insight, bool) {
	for _, in := range insights {
		if in.Type == typ {
			return in, true
		}
	}
	return Insight{}, false
}

func TestClassifyCertificate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(*store.Certificate)
		wantType    string
		wantSev     Severity
		wantRec     string
		expectEmpty bool
	}{
		{"healthy => no insight", func(c *store.Certificate) {}, "", "", "", true},
		{"expired", func(c *store.Certificate) { c.Status = "expired" }, "expired", SeverityHigh, RecPlanRenewal, false},
		{"revoked", func(c *store.Certificate) { c.Status = "revoked" }, "revoked", SeverityCritical, RecPlanRenewal, false},
		{"expiring_soon", func(c *store.Certificate) { c.Status = "expiring_soon"; c.DaysUntilExpiry = 12 }, "expiring_soon", SeverityMedium, RecPlanRenewal, false},
		{"incomplete_chain", func(c *store.Certificate) { c.ChainStatus = "incomplete" }, "incomplete_chain", SeverityMedium, RecRescan, false},
		{"untrusted_root", func(c *store.Certificate) { c.ChainStatus = "untrusted_root" }, "untrusted_root", SeverityMedium, RecImportCA, false},
		{"san_mismatch", func(c *store.Certificate) { c.HostnameMatchesSAN = false }, "san_mismatch", SeverityLow, RecFixSAN, false},
		{"weak_key", func(c *store.Certificate) { c.KeyBits = 1024 }, "weak_key", SeverityHigh, RecPlanRenewal, false},
		{"shadow_internal", func(c *store.Certificate) { c.ManagedStatus = "unmanaged"; c.CertScope = "internal" }, "shadow_internal", SeverityLow, RecReconcileVault, false},
		{"shadow_external", func(c *store.Certificate) { c.ManagedStatus = "unmanaged"; c.CertScope = "external" }, "shadow_external", SeverityInfo, RecMonitorExternal, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseCert()
			tt.mutate(&c)
			got := ClassifyCertificate(c)
			if tt.expectEmpty {
				if len(got) != 0 {
					t.Fatalf("expected no insights, got %+v", got)
				}
				return
			}
			in, ok := hasInsight(got, tt.wantType)
			if !ok {
				t.Fatalf("expected insight type %q, got %+v", tt.wantType, got)
			}
			if in.Severity != tt.wantSev {
				t.Fatalf("severity = %q, want %q", in.Severity, tt.wantSev)
			}
			if in.Recommendation != tt.wantRec {
				t.Fatalf("recommendation = %q, want %q", in.Recommendation, tt.wantRec)
			}
		})
	}
}

func TestClassifyCertificate_MultipleInsights(t *testing.T) {
	t.Parallel()

	c := baseCert()
	c.Status = "expired"
	c.HostnameMatchesSAN = false
	c.ManagedStatus = "unmanaged"
	c.CertScope = "internal"

	got := ClassifyCertificate(c)
	for _, typ := range []string{"expired", "san_mismatch", "shadow_internal"} {
		if _, ok := hasInsight(got, typ); !ok {
			t.Fatalf("expected insight %q in %+v", typ, got)
		}
	}
}

func TestClassifyAll_SortedBySeverity(t *testing.T) {
	t.Parallel()

	low := baseCert()
	low.HostnameMatchesSAN = false // low
	high := baseCert()
	high.Status = "expired" // high

	all := ClassifyAll([]store.Certificate{low, high})
	if len(all) < 2 {
		t.Fatalf("expected >=2 insights, got %d", len(all))
	}
	if severityRank(all[0].Severity) < severityRank(all[len(all)-1].Severity) {
		t.Fatalf("insights not sorted by severity desc: %+v", all)
	}
}
