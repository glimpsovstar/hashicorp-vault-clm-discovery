package scanner

import (
	"strings"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/demo"
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

func TestExpandHostnames(t *testing.T) {
	targets, err := ExpandHostnames([]string{"example.com"}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("expected targets")
	}
	if targets[0].Hostname != "example.com" {
		t.Fatalf("expected hostname example.com, got %q", targets[0].Hostname)
	}
	if targets[0].Port != 443 {
		t.Fatalf("unexpected port %d", targets[0].Port)
	}
}

func TestExpandScanTargetsRequiresInput(t *testing.T) {
	_, _, err := ExpandScanTargets(nil, nil, []int{443}, true)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestExpandHostnamesPartialSkipsUnresolvable(t *testing.T) {
	targets, warnings, err := ExpandHostnamesPartial(
		[]string{"example.com", "this-host-should-not-resolve.invalid"},
		[]int{443},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("expected targets from example.com")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	foundExample := false
	for _, tg := range targets {
		if tg.Hostname == "example.com" && tg.Port == 443 {
			foundExample = true
		}
	}
	if !foundExample {
		t.Fatalf("expected example.com target, got %+v", targets)
	}
}

func TestExpandScanTargetsPartialSkipsBadHostnamesWhenCIDRsPresent(t *testing.T) {
	targets, warnings, err := ExpandScanTargets(
		[]string{"127.0.0.1/32"},
		[]string{"this-host-should-not-resolve.invalid"},
		[]int{443},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 CIDR target, got %d", len(targets))
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 hostname warning, got %d: %v", len(warnings), warnings)
	}
}

func TestExpandScanTargetsPartialDemoMix(t *testing.T) {
	// Legacy wrong AAP domain used hashicorp.io; demo uses hashidemos.io (demo.ScanHostnames).
	// Append .invalid so the test does not depend on hashicorp.io DNS (that name now resolves).
	wrongAAP := "aap.david-joo.sbx.hashicorp.io.invalid"
	good := demo.ScanHostnames[1] // coffeesnob.withdevo.net

	targets, warnings, err := ExpandScanTargets(nil, []string{wrongAAP, good}, []int{443}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("expected targets from resolvable demo hostname")
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning for wrong AAP domain, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], wrongAAP) {
		t.Fatalf("expected warning about %q, got %q", wrongAAP, warnings[0])
	}
	found := false
	for _, tg := range targets {
		if tg.Hostname == good {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected target for %q, got %+v", good, targets)
	}
}

func TestExpandHostnamesPartialAllFail(t *testing.T) {
	_, warnings, err := ExpandHostnamesPartial(
		[]string{"this-host-should-not-resolve.invalid"},
		[]int{443},
	)
	if err == nil {
		t.Fatal("expected error when no hostnames resolve")
	}
	if len(warnings) == 0 {
		t.Fatal("expected warnings")
	}
}
