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
