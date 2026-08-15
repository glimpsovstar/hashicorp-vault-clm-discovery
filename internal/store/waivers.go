package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrWaiverNotFound = errors.New("waiver not found")
	ErrWaiverExpired  = errors.New("waiver expired")
)

// Waiver is an acknowledgement that suppresses score/count for a finding
// without hiding the finding row.
type Waiver struct {
	ID        uuid.UUID  `json:"id"`
	CertID    uuid.UUID  `json:"cert_id"`
	RuleID    string     `json:"rule_id"`
	Reason    string     `json:"reason"`
	CreatedBy string     `json:"created_by"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ActiveWaiver looks up a non-revoked, non-expired waiver for cert+rule.
func (s *Store) ActiveWaiver(ctx context.Context, certID uuid.UUID, ruleID string, now time.Time) (*Waiver, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, cert_id, rule_id, reason, created_by, expires_at, created_at, revoked_at
		FROM waivers
		WHERE cert_id = $1 AND rule_id = $2
		  AND revoked_at IS NULL
		  AND expires_at > $3
		ORDER BY expires_at DESC
		LIMIT 1
	`, certID, ruleID, now)
	var w Waiver
	err := row.Scan(&w.ID, &w.CertID, &w.RuleID, &w.Reason, &w.CreatedBy, &w.ExpiresAt, &w.CreatedAt, &w.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// ListWaiversForCert returns all waivers for a certificate (including expired).
func (s *Store) ListWaiversForCert(ctx context.Context, certID uuid.UUID) ([]Waiver, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cert_id, rule_id, reason, created_by, expires_at, created_at, revoked_at
		FROM waivers
		WHERE cert_id = $1
		ORDER BY created_at DESC
	`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Waiver
	for rows.Next() {
		var w Waiver
		if err := rows.Scan(&w.ID, &w.CertID, &w.RuleID, &w.Reason, &w.CreatedBy, &w.ExpiresAt, &w.CreatedAt, &w.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	if out == nil {
		out = []Waiver{}
	}
	return out, rows.Err()
}

// CreateWaiver inserts a waiver. Actor is required (M1).
func (s *Store) CreateWaiver(ctx context.Context, certID uuid.UUID, ruleID, reason, actor string, expiresAt time.Time) (Waiver, error) {
	if actor == "" {
		return Waiver{}, errors.New("waiver actor required")
	}
	if reason == "" {
		return Waiver{}, errors.New("waiver reason required")
	}
	if !expiresAt.After(time.Now().UTC()) {
		return Waiver{}, ErrWaiverExpired
	}
	var w Waiver
	err := s.pool.QueryRow(ctx, `
		INSERT INTO waivers (cert_id, rule_id, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, cert_id, rule_id, reason, created_by, expires_at, created_at, revoked_at
	`, certID, ruleID, reason, actor, expiresAt.UTC()).Scan(
		&w.ID, &w.CertID, &w.RuleID, &w.Reason, &w.CreatedBy, &w.ExpiresAt, &w.CreatedAt, &w.RevokedAt,
	)
	return w, err
}

// RevokeWaiver soft-deletes a waiver by id.
func (s *Store) RevokeWaiver(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE waivers SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL
	`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrWaiverNotFound
	}
	return nil
}

// GetWaiver loads a waiver by id.
func (s *Store) GetWaiver(ctx context.Context, id uuid.UUID) (Waiver, error) {
	var w Waiver
	err := s.pool.QueryRow(ctx, `
		SELECT id, cert_id, rule_id, reason, created_by, expires_at, created_at, revoked_at
		FROM waivers WHERE id = $1
	`, id).Scan(&w.ID, &w.CertID, &w.RuleID, &w.Reason, &w.CreatedBy, &w.ExpiresAt, &w.CreatedAt, &w.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Waiver{}, ErrWaiverNotFound
	}
	return w, err
}
