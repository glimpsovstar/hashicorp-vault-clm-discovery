package lifecyclejobs

import (
	"testing"
	"time"
)

func TestNextVerifyDelay(t *testing.T) {
	t.Parallel()
	if NextVerifyDelay(1) != 10*time.Second {
		t.Fatal(NextVerifyDelay(1))
	}
	if NextVerifyDelay(3) != 60*time.Second {
		t.Fatal(NextVerifyDelay(3))
	}
	if NextVerifyDelay(8) != 6*time.Hour {
		t.Fatal(NextVerifyDelay(8))
	}
	if NextVerifyDelay(99) != 6*time.Hour {
		t.Fatal("cap")
	}
	if NextVerifyDelay(0) != 10*time.Second {
		t.Fatal("zero")
	}
}

func TestVerifyDelay(t *testing.T) {
	t.Parallel()
	want := []time.Duration{
		10 * time.Second, 30 * time.Second, 60 * time.Second,
		5 * time.Minute, 30 * time.Minute, 60 * time.Minute,
		3 * time.Hour, 6 * time.Hour, 6 * time.Hour,
	}
	for i, d := range want {
		if got := VerifyDelay(i + 1); got != d {
			t.Fatalf("attempt %d: got %v want %v", i+1, got, d)
		}
	}
}

func TestNextVerifyAt_CapsAtTimeout(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	timeout := now.Add(15 * time.Second)
	next, last := NextVerifyAt(now, 1, timeout)
	if last || !next.Equal(now.Add(10*time.Second)) {
		t.Fatalf("next=%v last=%v", next, last)
	}
	next, last = NextVerifyAt(now, 3, timeout)
	if !last || !next.Equal(timeout) {
		t.Fatalf("expected last attempt at timeout, got next=%v last=%v", next, last)
	}
}
