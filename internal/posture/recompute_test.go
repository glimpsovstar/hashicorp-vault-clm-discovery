package posture

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type fakePostureStore struct {
	cert     store.Certificate
	findings []store.FindingUpsert
	score    int
	reasons  []store.RiskReason
	waivers  map[string]*store.Waiver
	policyID *uuid.UUID
}

func (f *fakePostureStore) GetCertificate(context.Context, uuid.UUID) (store.Certificate, error) {
	c := f.cert
	c.RiskScore = f.score
	c.RiskReasons = f.reasons
	return c, nil
}

func (f *fakePostureStore) ListCertificates(context.Context, store.CertificateFilter) ([]store.Certificate, int, error) {
	return []store.Certificate{f.cert}, 1, nil
}

func (f *fakePostureStore) UpsertFindings(_ context.Context, _ uuid.UUID, current []store.FindingUpsert) ([]store.FindingRow, error) {
	f.findings = current
	var rows []store.FindingRow
	for _, c := range current {
		rows = append(rows, store.FindingRow{
			CertID: c.CertID, RuleID: c.RuleID, Pack: c.Pack, Severity: c.Severity,
			Title: c.Title, Detail: c.Detail, Status: "open", Waived: c.Waived,
		})
	}
	return rows, nil
}

func (f *fakePostureStore) UpdateCertificateRisk(_ context.Context, _ uuid.UUID, score int, reasons []store.RiskReason) error {
	f.score = score
	f.reasons = reasons
	return nil
}

func (f *fakePostureStore) CurrentOpsPolicyVersionID(context.Context) (*uuid.UUID, error) {
	return f.policyID, nil
}

func (f *fakePostureStore) ActiveWaiver(_ context.Context, _ uuid.UUID, ruleID string, _ time.Time) (*store.Waiver, error) {
	if f.waivers == nil {
		return nil, nil
	}
	return f.waivers[ruleID], nil
}

func TestRecomputeCert_CriticalBandAndNoWarning(t *testing.T) {
	t.Parallel()
	cn := "expired.example.com"
	env := "prod"
	pid := uuid.New()
	st := &fakePostureStore{
		policyID: &pid,
		cert: store.Certificate{
			ID: uuid.New(), FingerprintSHA256: "fp", SubjectCN: &cn,
			Status: "expired", DaysUntilExpiry: -2, ManagedStatus: "unmanaged",
			CertScope: "internal", Environment: &env,
			NotAfter: time.Now().UTC().Add(-48 * time.Hour),
			NotBefore: time.Now().UTC().Add(-400 * 24 * time.Hour),
			KeyType: "RSA", KeyBits: 2048, SignatureAlgorithm: "SHA256-RSA",
			HostnameMatchesSAN: true, ChainStatus: "complete",
		},
	}
	got, err := RecomputeCert(context.Background(), st, st.cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RiskScore < 80 {
		t.Fatalf("risk_score=%d want critical band (≥80)", got.RiskScore)
	}
	if len(got.RiskReasons) == 0 {
		t.Fatal("expected risk_reasons")
	}
	for _, f := range st.findings {
		if f.Severity == "warning" {
			t.Fatalf("persisted warning severity for %s", f.RuleID)
		}
	}
}

func TestRecomputeCert_WaiverSuppressesScore(t *testing.T) {
	t.Parallel()
	cn := "expired.example.com"
	env := "prod"
	certID := uuid.New()
	st := &fakePostureStore{
		cert: store.Certificate{
			ID: certID, FingerprintSHA256: "fp2", SubjectCN: &cn,
			Status: "expired", DaysUntilExpiry: -2, ManagedStatus: "managed_in_vault",
			CertScope: "internal", Environment: &env,
			NotAfter: time.Now().UTC().Add(-48 * time.Hour),
			NotBefore: time.Now().UTC().Add(-400 * 24 * time.Hour),
			KeyType: "RSA", KeyBits: 2048, SignatureAlgorithm: "SHA256-RSA",
			HostnameMatchesSAN: true, ChainStatus: "complete",
		},
		waivers: map[string]*store.Waiver{},
	}
	// Pre-seed waiver keys after we know which rules fire.
	raw := EvaluateCertAll(st.cert)
	for _, f := range raw {
		mapped := compliance.MapFindingForPersist(f)
		st.waivers[mapped.RuleID] = &store.Waiver{RuleID: mapped.RuleID, CertID: certID}
	}

	got, err := RecomputeCert(context.Background(), st, certID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RiskScore != 0 {
		t.Fatalf("waived risk_score=%d want 0", got.RiskScore)
	}
	if len(got.RiskReasons) == 0 {
		t.Fatal("waivers must not hide risk_reasons")
	}
	for _, r := range got.RiskReasons {
		if !r.Waived {
			t.Fatalf("expected waived reason for %s", r.RuleID)
		}
	}
}

func TestScoreFromFindings_MaxNonWaived(t *testing.T) {
	t.Parallel()
	score, reasons := scoreFromFindings([]store.FindingRow{
		{RuleID: "a", Severity: "info", Waived: false},
		{RuleID: "b", Severity: "critical", Waived: true},
		{RuleID: "c", Severity: "high", Waived: false},
	})
	if score != compliance.ScoreHigh {
		t.Fatalf("score=%d want %d", score, compliance.ScoreHigh)
	}
	if len(reasons) != 3 {
		t.Fatalf("reasons=%d", len(reasons))
	}
}
