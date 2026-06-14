package demo

import (
	"net"
	"os"
	"strings"
	"testing"
)

func TestScanHostnamesNotWrongAAPDomain(t *testing.T) {
	for _, host := range ScanHostnames {
		if strings.Contains(host, "hashicorp.io") {
			t.Fatalf("demo hostname must use hashidemos.io, not hashicorp.io: %q", host)
		}
		if strings.Contains(host, "aap.") && !strings.Contains(host, "hashidemos.io") {
			t.Fatalf("AAP demo hostname must be on hashidemos.io: %q", host)
		}
	}
}

func TestValidateScanHostnameRejectsURLs(t *testing.T) {
	cases := []string{
		"https://aap.david-joo.sbx.hashidemos.io/",
		"http://example.com",
		"example.com/path",
		"example.com?x=1",
		"",
		" ",
	}
	for _, c := range cases {
		if err := ValidateScanHostname(c); err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

func TestValidateScanHostnameAcceptsDemoHostnames(t *testing.T) {
	for _, host := range ScanHostnames {
		if err := ValidateScanHostname(host); err != nil {
			t.Fatalf("demo hostname %q invalid: %v", host, err)
		}
	}
}

func TestWebDemoHostnamesMatchGo(t *testing.T) {
	body, err := os.ReadFile("../../web/lib/demo-hostnames.ts")
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	if strings.Contains(content, "hashicorp.io") {
		t.Fatal("web/lib/demo-hostnames.ts must not contain hashicorp.io")
	}
	for _, host := range ScanHostnames {
		if !strings.Contains(content, host) {
			t.Fatalf("web/lib/demo-hostnames.ts missing %q", host)
		}
	}
}

func TestDemoHostnamesResolve(t *testing.T) {
	if os.Getenv("SKIP_DEMO_DNS") == "1" {
		t.Skip("SKIP_DEMO_DNS=1")
	}
	for _, host := range ScanHostnames {
		addrs, err := net.LookupHost(host)
		if err != nil {
			t.Errorf("demo hostname %q should resolve: %v", host, err)
			continue
		}
		if len(addrs) == 0 {
			t.Errorf("demo hostname %q returned no addresses", host)
		}
	}
}
