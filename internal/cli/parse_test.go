package cli

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("443, 8443 ,6443")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{443, 8443, 6443}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
}

func TestParsePortsRejectsInvalid(t *testing.T) {
	if _, err := ParsePorts("443,abc"); err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

func TestSplitCSV(t *testing.T) {
	got := SplitCSV(" 203.0.113.0/24 , , example.com ")
	want := []string{"203.0.113.0/24", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSplitCSVEmpty(t *testing.T) {
	if got := SplitCSV(""); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
	if got := SplitCSV("  ,  "); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}
