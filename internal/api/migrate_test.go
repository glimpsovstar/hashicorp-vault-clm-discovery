package api

import (
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestMigrateEligible(t *testing.T) {
	t.Parallel()
	cn := "app.example.com"
	leaf := store.Certificate{SubjectCN: &cn, ManagedStatus: "unmanaged", IsCA: false}
	if err := migrateEligible(leaf, true, false); err != nil {
		t.Fatal(err)
	}
	if err := migrateEligible(store.Certificate{SubjectCN: &cn, IsCA: true}, true, false); !errorsIs(err, errMigrateCA) {
		t.Fatalf("got %v", err)
	}
	if err := migrateEligible(store.Certificate{SubjectCN: &cn, ManagedStatus: "managed_in_vault"}, true, false); !errorsIs(err, errMigrateManaged) {
		t.Fatalf("got %v", err)
	}
	if err := migrateEligible(store.Certificate{ManagedStatus: "unmanaged"}, true, false); !errorsIs(err, errMigrateNoCN) {
		t.Fatalf("got %v", err)
	}
	if err := migrateEligible(leaf, false, false); !errorsIs(err, errMigrateNoObservation) {
		t.Fatalf("got %v", err)
	}
	if err := migrateEligible(leaf, true, true); !errorsIs(err, errMigrateOpenJob) {
		t.Fatalf("got %v", err)
	}
}

func errorsIs(err, target error) bool {
	return err != nil && target != nil && err.Error() == target.Error()
}
