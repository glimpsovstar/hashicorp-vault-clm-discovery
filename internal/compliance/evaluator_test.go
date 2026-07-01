package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestEvaluateCert_AggregatesAllPacks(t *testing.T) {
	t.Parallel()

	env := "prod"
	cert := store.Certificate{
		ID:                 uuid.New(),
		FingerprintSHA256:  "agg-fp",
		SubjectCN:          strPtr("bad.example.com"),
		NotBefore:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
		KeyType:            "RSA",
		KeyBits:            1024,
		SignatureAlgorithm: "SHA1-RSA",
		CertScope:          governance.ScopeExternal,
		Environment:        &env,
		ManagedStatus:      "unmanaged",
		DaysUntilExpiry:    300,
	}

	findings := EvaluateCert(cert)
	packs := map[string]bool{}
	for _, f := range findings {
		packs[f.Pack] = true
	}
	for _, pack := range []string{"sc081", "pci", "crypto"} {
		if !packs[pack] {
			t.Fatalf("missing pack %q in %+v", pack, findings)
		}
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical findings first, got %q", findings[0].Severity)
	}
}

func TestEvaluateCerts_BuildsSummary(t *testing.T) {
	t.Parallel()

	certs := []store.Certificate{
		{
			ID:                uuid.New(),
			FingerprintSHA256: "c1",
			SubjectCN:         strPtr("a.example.com"),
			NotBefore:         time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:          time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
			KeyType:           "RSA",
			KeyBits:           4096,
			SignatureAlgorithm: "SHA256-RSA",
			CertScope:         governance.ScopeInternal,
			DaysUntilExpiry:   300,
		},
		{
			ID:                 uuid.New(),
			FingerprintSHA256:  "c2",
			SubjectCN:          strPtr("b.example.com"),
			NotBefore:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:           time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
			KeyType:            "RSA",
			KeyBits:            1024,
			SignatureAlgorithm: "SHA1-RSA",
			CertScope:          governance.ScopeExternal,
			DaysUntilExpiry:    300,
		},
	}

	summary := EvaluateCerts(certs)
	if summary.TotalCerts != 2 {
		t.Fatalf("total = %d, want 2", summary.TotalCerts)
	}
	if summary.SC081ViolationCount < 1 {
		t.Fatalf("sc081 violations = %d, want >= 1", summary.SC081ViolationCount)
	}
	if summary.AlgorithmInventory.RSA2048Plus != 1 || summary.AlgorithmInventory.RSAUnder2048 != 1 {
		t.Fatalf("algorithm inventory = %+v", summary.AlgorithmInventory)
	}
}

type fakeCertStore struct {
	certs []store.Certificate
	err   error
}

func (f *fakeCertStore) ListCertificates(_ context.Context, filter store.CertificateFilter) ([]store.Certificate, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.Offset >= len(f.certs) {
		return nil, len(f.certs), nil
	}
	end := filter.Offset + filter.Limit
	if end > len(f.certs) {
		end = len(f.certs)
	}
	return f.certs[filter.Offset:end], len(f.certs), nil
}

func TestCountSC081Violations_CountsOnlySC081Pack(t *testing.T) {
	t.Parallel()

	st := &fakeCertStore{
		certs: []store.Certificate{
			{
				// Exceeds the 199-day ceiling -> one sc081 finding.
				ID:                 uuid.New(),
				FingerprintSHA256:  "over-ceiling",
				SubjectCN:          strPtr("a.example.com"),
				NotBefore:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
				KeyType:            "RSA",
				KeyBits:            2048,
				SignatureAlgorithm: "SHA256-RSA",
				CertScope:          governance.ScopeExternal,
				DaysUntilExpiry:    300,
			},
			{
				// Weak key + missing owner trigger crypto/pci findings, but the
				// 180-day validity and far-off expiry mean zero sc081 findings.
				ID:                 uuid.New(),
				FingerprintSHA256:  "no-sc081",
				SubjectCN:          strPtr("b.example.com"),
				NotBefore:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:           time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 180),
				KeyType:            "RSA",
				KeyBits:            1024,
				SignatureAlgorithm: "SHA1-RSA",
				CertScope:          governance.ScopeExternal,
				DaysUntilExpiry:    300,
			},
		},
	}

	count, err := CountSC081Violations(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("sc081 violations = %d, want 1", count)
	}
}

func TestSC081ViolationCount_ExcludesInfoSeverity(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	// Internal, non-prod cert expiring in 10 days: SC-081 downgrades the expiry
	// finding to "info". It is a finding, but not a violation, so the headline
	// SC-081 violation count must not include it.
	certs := []store.Certificate{
		{
			ID:                 uuid.New(),
			FingerprintSHA256:  "internal-soon",
			SubjectCN:          strPtr("internal.local"),
			NotBefore:          now.AddDate(0, 0, -3),
			NotAfter:           now.AddDate(0, 0, 10),
			KeyType:            "RSA",
			KeyBits:            2048,
			SignatureAlgorithm: "SHA256-RSA",
			CertScope:          governance.ScopeInternal,
		},
	}

	summary := EvaluateCerts(certs)
	if summary.SC081ViolationCount != 0 {
		t.Fatalf("SC081ViolationCount = %d, want 0 (info-severity finding is not a violation)", summary.SC081ViolationCount)
	}

	count, err := CountSC081Violations(context.Background(), &fakeCertStore{certs: certs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("CountSC081Violations = %d, want 0 (info-severity finding is not a violation)", count)
	}
}

func TestEvaluateScan_WithScanFilter(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	st := &fakeCertStore{
		certs: []store.Certificate{
			{
				ID:                uuid.New(),
				FingerprintSHA256: "scan-cert",
				SubjectCN:         strPtr("scan.example.com"),
				NotBefore:         time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:          time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
				KeyType:           "RSA",
				KeyBits:           2048,
				SignatureAlgorithm: "SHA256-RSA",
				CertScope:         governance.ScopeExternal,
				DaysUntilExpiry:   300,
			},
		},
	}

	summary, err := EvaluateScan(context.Background(), st, &scanID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ScanID != scanID {
		t.Fatalf("scan_id = %s, want %s", summary.ScanID, scanID)
	}
	if summary.TotalCerts != 1 {
		t.Fatalf("total = %d, want 1", summary.TotalCerts)
	}
}
