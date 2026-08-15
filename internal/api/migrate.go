package api

import (
	"errors"
	"strings"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

var (
	errMigrateCA            = errors.New("CA certificates use Import CA (Mode B), not Migrate to Vault")
	errMigrateManaged       = errors.New("certificate is already managed in Vault; use /renew")
	errMigrateNoCN          = errors.New("certificate has no common name")
	errMigrateNoObservation = errors.New("certificate has no observation target for wire verify")
	errMigrateOpenJob       = errors.New("an open migrate job already exists for this certificate")
)

// migrateEligible reports whether a leaf can start Mode C migrate.
func migrateEligible(c store.Certificate, hasObservation bool, openMigrate bool) error {
	if c.IsCA {
		return errMigrateCA
	}
	if c.ManagedStatus == "managed_in_vault" {
		return errMigrateManaged
	}
	cn := ""
	if c.SubjectCN != nil {
		cn = strings.TrimSpace(*c.SubjectCN)
	}
	if cn == "" {
		return errMigrateNoCN
	}
	if !hasObservation {
		return errMigrateNoObservation
	}
	if openMigrate {
		return errMigrateOpenJob
	}
	return nil
}

func hasOpenMigrateStatus(status string) bool {
	switch status {
	case store.LifecycleVerified, store.LifecycleTimedOut, store.LifecycleFailed, store.LifecycleVerifyFailed:
		return false
	case "":
		return false
	default:
		return true
	}
}
