package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ManagedStatusUpdate sets Vault reconciliation fields on a certificate row.
type ManagedStatusUpdate struct {
	ManagedStatus  string
	VaultPKIMount  string
	VaultIssuerRef *string
	SerialNumber   string
}

// UpdateManagedStatusByFingerprint marks a CLM cert as Vault-managed when fingerprint matches.
// Returns true when a row was updated.
func (s *Store) UpdateManagedStatusByFingerprint(ctx context.Context, fingerprint string, u ManagedStatusUpdate) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE certificates SET
			managed_status = $2,
			vault_pki_mount = $3,
			vault_issuer_ref = $4,
			serial_number = $5,
			updated_at = NOW()
		WHERE fingerprint_sha256 = $1
	`, fingerprint, u.ManagedStatus, u.VaultPKIMount, u.VaultIssuerRef, u.SerialNumber)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CountByManagedStatus returns managed_in_vault and total discovered cert counts.
// When scanID is non-nil, counts only certificates observed in that scan.
func (s *Store) CountByManagedStatus(ctx context.Context, scanID *uuid.UUID) (managed, discovered int, err error) {
	where := ""
	args := []any{}
	if scanID != nil {
		where = ` WHERE EXISTS (
			SELECT 1 FROM certificate_observations o
			WHERE o.certificate_id = c.id AND o.scan_id = $1
		)`
		args = append(args, *scanID)
	}

	query := fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE c.managed_status = 'managed_in_vault'),
			COUNT(*)
		FROM certificates c%s
	`, where)

	err = s.pool.QueryRow(ctx, query, args...).Scan(&managed, &discovered)
	return managed, discovered, err
}
