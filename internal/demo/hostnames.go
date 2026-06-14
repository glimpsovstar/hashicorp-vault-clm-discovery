package demo

import (
	"fmt"
	"strings"
)

// ScanHostnames are the default demo targets for TLS discovery scans.
// Keep in sync with web/lib/demo-hostnames.ts (enforced by demo/hostnames_test.go).
var ScanHostnames = []string{
	"aap.david-joo.sbx.hashidemos.io",
	"coffeesnob.withdevo.net",
}

// ScanHostnamesCSV is the comma-separated form used in scan UIs and docs.
func ScanHostnamesCSV() string {
	return strings.Join(ScanHostnames, ",")
}

// ValidateScanHostname rejects URLs, paths, and empty values.
func ValidateScanHostname(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty hostname")
	}
	if strings.Contains(host, "://") {
		return fmt.Errorf("hostname must not include a URL scheme: %q", host)
	}
	if strings.ContainsAny(host, "/?#") {
		return fmt.Errorf("hostname must not include path or query: %q", host)
	}
	if strings.HasSuffix(host, ".") {
		return fmt.Errorf("hostname must not have trailing dot: %q", host)
	}
	if strings.Contains(host, " ") {
		return fmt.Errorf("hostname contains spaces: %q", host)
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("hostname must have at least two labels: %q", host)
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname has empty label: %q", host)
		}
	}
	return nil
}