package lifecycle

import (
	"testing"
	"time"
)

func TestComputeExpired(t *testing.T) {
	status, days := Compute(time.Now().UTC().Add(-24*time.Hour), 30, false)
	if status != StatusExpired {
		t.Fatalf("expected expired, got %s", status)
	}
	if days >= 0 {
		t.Fatalf("expected negative days, got %d", days)
	}
}

func TestComputeExpiringSoon(t *testing.T) {
	status, days := Compute(time.Now().UTC().Add(10*24*time.Hour), 30, false)
	if status != StatusExpiringSoon {
		t.Fatalf("expected expiring_soon, got %s", status)
	}
	if days != 10 && days != 9 {
		t.Fatalf("unexpected days: %d", days)
	}
}

func TestComputeValid(t *testing.T) {
	status, _ := Compute(time.Now().UTC().Add(90*24*time.Hour), 30, false)
	if status != StatusValid {
		t.Fatalf("expected valid, got %s", status)
	}
}

func TestComputeRevoked(t *testing.T) {
	status, _ := Compute(time.Now().UTC().Add(90*24*time.Hour), 30, true)
	if status != StatusRevoked {
		t.Fatalf("expected revoked, got %s", status)
	}
}
