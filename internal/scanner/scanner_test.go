package scanner

import (
	"testing"
)

func TestExpandTargetsSingleHost(t *testing.T) {
	targets, err := ExpandTargets([]string{"203.0.113.1/32"}, []int{443}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].IP != "203.0.113.1" || targets[0].Port != 443 {
		t.Fatalf("unexpected target: %+v", targets[0])
	}
}

func TestExpandTargetsBlocksPrivateByDefault(t *testing.T) {
	_, err := ExpandTargets([]string{"10.0.0.0/24"}, []int{443}, false)
	if err == nil {
		t.Fatal("expected error for private range")
	}
}

func TestExpandTargetsAllowsPrivateWhenEnabled(t *testing.T) {
	targets, err := ExpandTargets([]string{"127.0.0.1/32"}, []int{443, 8443}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestExpandTargetsRejectsLargeCIDR(t *testing.T) {
	_, err := ExpandTargets([]string{"0.0.0.0/8"}, []int{443}, true)
	if err == nil {
		t.Fatal("expected error for large cidr")
	}
}
