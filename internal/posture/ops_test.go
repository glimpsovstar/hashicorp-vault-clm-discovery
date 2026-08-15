package posture

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestEvaluateOps_EmitsShadowAndDedupsExpiry(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	cert := store.Certificate{
		ID:                 uuid.New(),
		FingerprintSHA256:  "abc",
		SubjectCN:          &cn,
		Status:             "expired",
		DaysUntilExpiry:    -1,
		ManagedStatus:      "unmanaged",
		CertScope:          "internal",
		NotAfter:           time.Now().UTC().Add(-48 * time.Hour),
		KeyType:            "RSA",
		KeyBits:            2048,
		HostnameMatchesSAN: true,
		ChainStatus:        "complete",
	}

	sc081 := []compliance.Finding{{
		Pack: "sc081", RuleID: "sc081.expiry.expired", Severity: "critical",
	}}
	ops := EvaluateOps(cert, sc081)
	for _, f := range ops {
		if f.RuleID == "ops.expired" || f.RuleID == "ops.expiring_soon" {
			t.Fatalf("expected SC-081 expiry dedup, got %s", f.RuleID)
		}
		if f.Severity == "warning" {
			t.Fatal("ops must not emit pack warning")
		}
		if f.Pack != "ops" {
			t.Fatalf("pack=%q", f.Pack)
		}
	}
	foundShadow := false
	for _, f := range ops {
		if f.RuleID == "ops.shadow_internal" {
			foundShadow = true
		}
	}
	if !foundShadow {
		t.Fatal("expected ops.shadow_internal")
	}
}

func TestEvaluateCertAll_IncludesCrypto(t *testing.T) {
	t.Parallel()
	cn := "weak.example.com"
	cert := store.Certificate{
		ID:                 uuid.New(),
		FingerprintSHA256:  "def",
		SubjectCN:          &cn,
		Status:             "valid",
		DaysUntilExpiry:    100,
		ManagedStatus:      "managed_in_vault",
		CertScope:          "internal",
		NotBefore:          time.Now().UTC().Add(-30 * 24 * time.Hour),
		NotAfter:           time.Now().UTC().Add(100 * 24 * time.Hour),
		KeyType:            "RSA",
		KeyBits:            1024,
		SignatureAlgorithm: "SHA256-RSA",
		HostnameMatchesSAN: true,
		ChainStatus:        "complete",
	}
	findings := EvaluateCertAll(cert)
	if len(findings) == 0 {
		t.Fatal("expected at least crypto weak-key finding")
	}
	mapped := compliance.MapFindingForPersist(findings[0])
	if mapped.Severity == "warning" {
		t.Fatal("mapped severity must not be warning")
	}
}
