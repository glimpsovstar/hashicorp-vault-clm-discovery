package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FindingRow is a persisted compliance/ops finding (5-level severity only).
type FindingRow struct {
	ID              uuid.UUID  `json:"id"`
	CertID          uuid.UUID  `json:"cert_id"`
	RuleID          string     `json:"rule_id"`
	Pack            string     `json:"pack"`
	Severity        string     `json:"severity"`
	Title           string     `json:"title"`
	Detail          string     `json:"detail"`
	Status          string     `json:"status"`
	PolicyVersionID *uuid.UUID `json:"policy_version_id,omitempty"`
	Waived          bool       `json:"waived"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// FindingUpsert is the input for upserting an open finding.
type FindingUpsert struct {
	CertID          uuid.UUID
	RuleID          string
	Pack            string
	Severity        string
	Title           string
	Detail          string
	PolicyVersionID *uuid.UUID
	Waived          bool
}

// UpsertFindings writes current findings for a cert, resolves missing open ones,
// and returns the open rows after upsert.
func (s *Store) UpsertFindings(ctx context.Context, certID uuid.UUID, current []FindingUpsert) ([]FindingRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	seen := make([]string, 0, len(current))
	for _, f := range current {
		seen = append(seen, f.RuleID)
		_, err := tx.Exec(ctx, `
			INSERT INTO findings (
				cert_id, rule_id, pack, severity, title, detail, status,
				policy_version_id, waived, first_seen_at, last_seen_at
			) VALUES ($1,$2,$3,$4,$5,$6,'open',$7,$8,NOW(),NOW())
			ON CONFLICT (cert_id, rule_id) DO UPDATE SET
				pack = EXCLUDED.pack,
				severity = EXCLUDED.severity,
				title = EXCLUDED.title,
				detail = EXCLUDED.detail,
				status = 'open',
				policy_version_id = EXCLUDED.policy_version_id,
				waived = EXCLUDED.waived,
				last_seen_at = NOW(),
				resolved_at = NULL,
				updated_at = NOW()
		`, f.CertID, f.RuleID, f.Pack, f.Severity, f.Title, f.Detail, f.PolicyVersionID, f.Waived)
		if err != nil {
			return nil, err
		}
	}

	if len(seen) == 0 {
		_, err = tx.Exec(ctx, `
			UPDATE findings SET status = 'resolved', resolved_at = NOW(), updated_at = NOW()
			WHERE cert_id = $1 AND status = 'open'
		`, certID)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE findings SET status = 'resolved', resolved_at = NOW(), updated_at = NOW()
			WHERE cert_id = $1 AND status = 'open' AND NOT (rule_id = ANY($2::text[]))
		`, certID, seen)
	}
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListOpenFindings(ctx, certID)
}

// ListOpenFindings returns open findings for a certificate.
func (s *Store) ListOpenFindings(ctx context.Context, certID uuid.UUID) ([]FindingRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cert_id, rule_id, pack, severity, title, detail, status,
			policy_version_id, waived, first_seen_at, last_seen_at, resolved_at, created_at, updated_at
		FROM findings
		WHERE cert_id = $1 AND status = 'open'
		ORDER BY pack, rule_id
	`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		if err := rows.Scan(
			&f.ID, &f.CertID, &f.RuleID, &f.Pack, &f.Severity, &f.Title, &f.Detail, &f.Status,
			&f.PolicyVersionID, &f.Waived, &f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if out == nil {
		out = []FindingRow{}
	}
	return out, rows.Err()
}

// ListFindingsForScan returns open findings for certificates observed in a scan.
func (s *Store) ListFindingsForScan(ctx context.Context, scanID uuid.UUID) ([]FindingRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT f.id, f.cert_id, f.rule_id, f.pack, f.severity, f.title, f.detail, f.status,
			f.policy_version_id, f.waived, f.first_seen_at, f.last_seen_at, f.resolved_at, f.created_at, f.updated_at
		FROM findings f
		WHERE f.status = 'open'
		  AND EXISTS (
			SELECT 1 FROM certificate_observations o
			WHERE o.certificate_id = f.cert_id AND o.scan_id = $1
		  )
		ORDER BY f.severity, f.pack, f.rule_id
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		if err := rows.Scan(
			&f.ID, &f.CertID, &f.RuleID, &f.Pack, &f.Severity, &f.Title, &f.Detail, &f.Status,
			&f.PolicyVersionID, &f.Waived, &f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if out == nil {
		out = []FindingRow{}
	}
	return out, rows.Err()
}

// UpdateCertificateRisk writes risk_score + risk_reasons for a certificate.
func (s *Store) UpdateCertificateRisk(ctx context.Context, certID uuid.UUID, score int, reasons []RiskReason) error {
	if reasons == nil {
		reasons = []RiskReason{}
	}
	data, err := json.Marshal(reasons)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE certificates SET risk_score = $2, risk_reasons = $3, updated_at = NOW()
		WHERE id = $1
	`, certID, score, data)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrCertificateNotFound
	}
	return nil
}

// CurrentOpsPolicyVersionID returns the latest ops policy version id, or nil if none.
func (s *Store) CurrentOpsPolicyVersionID(ctx context.Context) (*uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM policy_versions WHERE kind = 'ops' ORDER BY version DESC LIMIT 1
	`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// CountPQCTags returns inventory counts keyed by pqc_tag.
func (s *Store) CountPQCTags(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT pqc_tag, COUNT(*) FROM certificates GROUP BY pqc_tag
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{
		"classic": 0,
		"hybrid":  0,
		"pqc":     0,
		"unknown": 0,
	}
	for rows.Next() {
		var tag string
		var n int
		if err := rows.Scan(&tag, &n); err != nil {
			return nil, err
		}
		out[tag] = n
	}
	return out, rows.Err()
}
