package store

import "testing"

func TestStringSliceForPGNil(t *testing.T) {
	got := stringSliceForPG(nil)
	if got == nil {
		t.Fatal("expected non-nil empty slice for PostgreSQL array column")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestStringSliceForPGPreservesValues(t *testing.T) {
	in := []string{"http://ocsp.example.com"}
	got := stringSliceForPG(in)
	if len(got) != 1 || got[0] != in[0] {
		t.Fatalf("unexpected result: %v", got)
	}
}
