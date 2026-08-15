package posture

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// Store is the persistence surface used by posture recompute.
type Store interface {
	GetCertificate(ctx context.Context, id uuid.UUID) (store.Certificate, error)
	ListCertificates(ctx context.Context, f store.CertificateFilter) ([]store.Certificate, int, error)
	UpsertFindings(ctx context.Context, certID uuid.UUID, current []store.FindingUpsert) ([]store.FindingRow, error)
	UpdateCertificateRisk(ctx context.Context, certID uuid.UUID, score int, reasons []store.RiskReason) error
	CurrentOpsPolicyVersionID(ctx context.Context) (*uuid.UUID, error)
	ActiveWaiver(ctx context.Context, certID uuid.UUID, ruleID string, now time.Time) (*store.Waiver, error)
}

// RecomputeCert evaluates packs+ops, upserts findings, and writes risk_score /
// risk_reasons. Waivers suppress score contribution but findings remain visible.
func RecomputeCert(ctx context.Context, st Store, certID uuid.UUID) (store.Certificate, error) {
	cert, err := st.GetCertificate(ctx, certID)
	if err != nil {
		return store.Certificate{}, err
	}
	policyID, err := st.CurrentOpsPolicyVersionID(ctx)
	if err != nil {
		return store.Certificate{}, err
	}

	raw := EvaluateCertAll(cert)
	now := time.Now().UTC()
	upserts := make([]store.FindingUpsert, 0, len(raw))
	for _, f := range raw {
		mapped := compliance.MapFindingForPersist(f)
		waived := false
		w, err := st.ActiveWaiver(ctx, cert.ID, mapped.RuleID, now)
		if err != nil {
			return store.Certificate{}, err
		}
		if w != nil {
			waived = true
		}
		upserts = append(upserts, store.FindingUpsert{
			CertID:          cert.ID,
			RuleID:          mapped.RuleID,
			Pack:            mapped.Pack,
			Severity:        mapped.Severity,
			Title:           mapped.Title,
			Detail:          mapped.Detail,
			PolicyVersionID: policyID,
			Waived:          waived,
		})
	}

	rows, err := st.UpsertFindings(ctx, cert.ID, upserts)
	if err != nil {
		return store.Certificate{}, err
	}

	score, reasons := scoreFromFindings(rows)
	if err := st.UpdateCertificateRisk(ctx, cert.ID, score, reasons); err != nil {
		return store.Certificate{}, err
	}
	return st.GetCertificate(ctx, cert.ID)
}

// RecomputeScan recomputes posture for every certificate observed in a scan.
func RecomputeScan(ctx context.Context, st Store, scanID uuid.UUID) error {
	certs, err := loadScanCerts(ctx, st, scanID)
	if err != nil {
		return err
	}
	for _, c := range certs {
		if _, err := RecomputeCert(ctx, st, c.ID); err != nil {
			return err
		}
	}
	return nil
}

func loadScanCerts(ctx context.Context, st Store, scanID uuid.UUID) ([]store.Certificate, error) {
	filter := store.CertificateFilter{ScanID: scanID, Limit: 500, Offset: 0}
	var all []store.Certificate
	for {
		batch, total, err := st.ListCertificates(ctx, filter)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		filter.Offset += len(batch)
		if filter.Offset >= total || len(batch) == 0 {
			break
		}
	}
	return all, nil
}

func scoreFromFindings(rows []store.FindingRow) (int, []store.RiskReason) {
	score := 0
	reasons := make([]store.RiskReason, 0, len(rows))
	for _, r := range rows {
		s := compliance.ScoreSeverity(r.Severity)
		reason := store.RiskReason{
			RuleID:   r.RuleID,
			Pack:     r.Pack,
			Severity: r.Severity,
			Title:    r.Title,
			Score:    s,
			Waived:   r.Waived,
		}
		reasons = append(reasons, reason)
		if r.Waived {
			continue
		}
		if s > score {
			score = s
		}
	}
	return score, reasons
}
