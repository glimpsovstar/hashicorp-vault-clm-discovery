package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrManagedByVault is returned when a catalog import (mode A) is attempted on a
// certificate that reconcile already marks managed_in_vault. That state is owned
// by reconcile and must not be overwritten by a manual catalog action.
var ErrManagedByVault = errors.New("certificate is managed in vault")

// SetManagedStatus sets the CLM management state for catalog import (mode A). It
// refuses to overwrite 'managed_in_vault' (owned by Vault reconcile) and returns
// ErrManagedByVault in that case, or ErrCertificateNotFound if the id is unknown.
// The guard is a single atomic UPDATE so a concurrent reconcile cannot be
// clobbered between a read and the write.
func (s *Store) SetManagedStatus(ctx context.Context, id uuid.UUID, status string) (Certificate, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE certificates SET managed_status = $2, updated_at = NOW()
		WHERE id = $1 AND managed_status <> 'managed_in_vault'
	`, id, status)
	if err != nil {
		return Certificate{}, err
	}
	if tag.RowsAffected() == 0 {
		// No row updated: either the id is unknown or it is managed_in_vault.
		// Distinguish the two so the API can return 404 vs 409.
		if _, err := s.GetCertificate(ctx, id); err != nil {
			return Certificate{}, err // ErrCertificateNotFound (or a real DB error)
		}
		return Certificate{}, ErrManagedByVault
	}
	return s.GetCertificate(ctx, id)
}

// ManagedStatusUpdate sets Vault reconciliation fields on a certificate row.
// It deliberately does not carry serial_number: reconcile matches by
// fingerprint, so the scan-parsed serial is already the authoritative value and
// must not be overwritten with Vault's differently-formatted (colon-hex) serial.
type ManagedStatusUpdate struct {
	ManagedStatus  string
	VaultPKIMount  string
	VaultIssuerRef *string
	// Revoked reflects Vault PKI revocation_time > 0 for the matched serial.
	// When true, the row's lifecycle status is set to 'revoked'; when false the
	// scan-derived status (valid/expiring_soon/expired) is preserved.
	Revoked bool
}

// UpdateManagedStatusByFingerprint marks a CLM cert as Vault-managed when fingerprint matches.
// Returns true when a row was updated.
func (s *Store) UpdateManagedStatusByFingerprint(ctx context.Context, fingerprint string, u ManagedStatusUpdate) (bool, error) {
	// revocation_checked_at is always stamped (we did read Vault). When revoked,
	// promote status to 'revoked' and record revocation_status; otherwise leave
	// the scan-derived lifecycle status untouched. revocation_status is only
	// cleared when it was reconcile's own marker, so a future OCSP/CRL source for
	// shadow certs is not wiped by a Vault reconcile pass.
	tag, err := s.pool.Exec(ctx, `
		UPDATE certificates SET
			managed_status = $2,
			vault_pki_mount = $3,
			vault_issuer_ref = $4,
			status = CASE WHEN $5 THEN 'revoked'::cert_status ELSE status END,
			revocation_status = CASE
				WHEN $5 THEN 'revoked_in_vault'
				WHEN revocation_status = 'revoked_in_vault' THEN NULL
				ELSE revocation_status
			END,
			revocation_checked_at = NOW(),
			updated_at = NOW()
		WHERE fingerprint_sha256 = $1
	`, fingerprint, u.ManagedStatus, u.VaultPKIMount, u.VaultIssuerRef, u.Revoked)
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
