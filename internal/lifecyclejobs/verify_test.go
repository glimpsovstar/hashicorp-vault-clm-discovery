package lifecyclejobs

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestMapAAPStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   aap.Status
		want string
	}{
		{aap.StatusPending, store.LifecycleAAPPending},
		{aap.StatusRunning, store.LifecycleAAPRunning},
		{aap.StatusSuccessful, store.LifecycleAAPSuccessful},
		{aap.StatusFailed, store.LifecycleFailed},
		{aap.StatusError, store.LifecycleFailed},
		{aap.StatusCanceled, store.LifecycleFailed},
	}
	for _, tc := range cases {
		if got := MapAAPStatus(tc.in); got != tc.want {
			t.Fatalf("MapAAPStatus(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVerifyWire(t *testing.T) {
	t.Parallel()
	predAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := predAfter.Add(24 * time.Hour)
	base := ExpectedWire{
		CommonName:          "app.example.com",
		PredecessorFP:       "fp-old",
		PredecessorNotAfter: predAfter,
	}
	tests := []struct {
		name string
		obs  ObservedWire
		ok   bool
	}{
		{"empty observed", ObservedWire{}, false},
		{"same fingerprint", ObservedWire{CommonName: "app.example.com", Fingerprint: "fp-old", NotAfter: later}, false},
		{"cn mismatch", ObservedWire{CommonName: "other", Fingerprint: "fp-new", NotAfter: later}, false},
		{"not_after not later", ObservedWire{CommonName: "app.example.com", Fingerprint: "fp-new", NotAfter: predAfter}, false},
		{"success", ObservedWire{CommonName: "app.example.com", Fingerprint: "fp-new", NotAfter: later}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := VerifyWire(base, tt.obs)
			if got.OK != tt.ok {
				t.Fatalf("OK = %v, want %v (reason %q)", got.OK, tt.ok, got.Reason)
			}
		})
	}
}

func TestRenewIdempotencyKeyStable(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	a := store.RenewIdempotencyKey(id, "fp")
	b := store.RenewIdempotencyKey(id, "fp")
	if a != b || a == "" {
		t.Fatalf("keys differ or empty: %q %q", a, b)
	}
	if store.RenewIdempotencyKey(id, "other") == a {
		t.Fatal("fingerprint change should change key")
	}
}
