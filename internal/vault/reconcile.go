package vault

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

// Summary captures Vault PKI reconciliation results.
type Summary struct {
	MountsScanned  int      `json:"mounts_scanned"`
	VaultCertsRead int      `json:"vault_certs_read"`
	Matched        int      `json:"matched"`
	UnmatchedCLM   int      `json:"unmatched_clm"`
	Errors         []string `json:"errors"`
}

// CertificateStore updates CLM inventory from Vault reconcile matches.
type CertificateStore interface {
	UpdateManagedStatusByFingerprint(ctx context.Context, fingerprint string, u store.ManagedStatusUpdate) (bool, error)
	CountByManagedStatus(ctx context.Context, scanID *uuid.UUID) (managed, discovered int, err error)
}

// PKIReader reads Vault PKI mounts and certificates.
type PKIReader interface {
	ListPKIMounts(ctx context.Context) ([]string, error)
	ListCertSerials(ctx context.Context, mount string) ([]string, error)
	ReadCert(ctx context.Context, mount, serial string) (string, map[string]interface{}, error)
}

// Reconciler correlates Vault PKI certificates with CLM inventory by fingerprint.
type Reconciler struct {
	pki   PKIReader
	store CertificateStore
}

func NewReconciler(pki PKIReader, st CertificateStore) *Reconciler {
	return &Reconciler{pki: pki, store: st}
}

func (r *Reconciler) Reconcile(ctx context.Context) (Summary, error) {
	var summary Summary

	mounts, err := r.pki.ListPKIMounts(ctx)
	if err != nil {
		return summary, fmt.Errorf("list PKI mounts: %w", err)
	}
	summary.MountsScanned = len(mounts)

	for _, mount := range mounts {
		serials, err := r.pki.ListCertSerials(ctx, mount)
		if err != nil {
			summary.Errors = append(summary.Errors, fmt.Sprintf("%s: list certs: %v", mount, err))
			continue
		}

		for _, serial := range serials {
			pemStr, meta, err := r.pki.ReadCert(ctx, mount, serial)
			if err != nil {
				summary.Errors = append(summary.Errors, fmt.Sprintf("%s cert %s: read: %v", mount, serial, err))
				continue
			}
			summary.VaultCertsRead++

			fp, err := FingerprintSHA256FromPEM(pemStr)
			if err != nil {
				summary.Errors = append(summary.Errors, fmt.Sprintf("%s cert %s: fingerprint: %v", mount, serial, err))
				continue
			}

			issuerRef := issuerRefFromMeta(meta)
			updated, err := r.store.UpdateManagedStatusByFingerprint(ctx, fp, store.ManagedStatusUpdate{
				ManagedStatus:  "managed_in_vault",
				VaultPKIMount:  normalizeMount(mount),
				VaultIssuerRef: issuerRef,
				SerialNumber:   vaultSerial(meta, serial),
			})
			if err != nil {
				summary.Errors = append(summary.Errors, fmt.Sprintf("%s cert %s: update store: %v", mount, serial, err))
				continue
			}
			if updated {
				summary.Matched++
			}
		}
	}

	managed, discovered, err := r.store.CountByManagedStatus(ctx, nil)
	if err != nil {
		return summary, fmt.Errorf("count managed status: %w", err)
	}
	summary.UnmatchedCLM = discovered - managed
	if summary.UnmatchedCLM < 0 {
		summary.UnmatchedCLM = 0
	}

	if summary.Errors == nil {
		summary.Errors = []string{}
	}
	return summary, nil
}

func issuerRefFromMeta(meta map[string]interface{}) *string {
	for _, key := range []string{"issuer_id", "issuer_name"} {
		if v, ok := meta[key].(string); ok && v != "" {
			return &v
		}
	}
	return nil
}

func vaultSerial(meta map[string]interface{}, fallback string) string {
	if v, ok := meta["serial_number"].(string); ok && v != "" {
		return v
	}
	return fallback
}
