package store

import (
	"testing"

	scanpkg "github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
)

func TestScanStatsRecordsProbeAndUpsertFailures(t *testing.T) {
	stats := &ScanStats{}
	target := scanpkg.Target{IP: "10.0.0.1", Port: 443, Hostname: "example.com"}

	stats.Scanned = 1
	stats.RecordProbeFailure(target, "timeout")
	stats.RecordProbeSuccess()
	stats.RecordUpsertFailure(target, "null value in column ocsp_servers")
	stats.RecordCertFound()

	summary := stats.Summary(2, []string{"skipped bad.example: NXDOMAIN"})

	if summary.TargetsFailed != 1 {
		t.Fatalf("targets_failed = %d, want 1", summary.TargetsFailed)
	}
	if summary.TargetsSucceeded != 1 {
		t.Fatalf("targets_succeeded = %d, want 1", summary.TargetsSucceeded)
	}
	if summary.UpsertFailures != 1 {
		t.Fatalf("upsert_failures = %d, want 1", summary.UpsertFailures)
	}
	if summary.CertsFound != 1 {
		t.Fatalf("certs_found = %d, want 1", summary.CertsFound)
	}
	if len(summary.ExpansionWarnings) != 1 {
		t.Fatalf("expansion_warnings = %#v", summary.ExpansionWarnings)
	}
	if len(summary.FailureSamples) != 2 {
		t.Fatalf("failure_samples = %#v, want 2 entries", summary.FailureSamples)
	}
	if summary.FailureSamples[1].Kind != "upsert" {
		t.Fatalf("second sample kind = %q, want upsert", summary.FailureSamples[1].Kind)
	}
	if summary.FailureSamples[1].Hostname != "example.com" {
		t.Fatalf("sample hostname = %q", summary.FailureSamples[1].Hostname)
	}
}

func TestScanStatsCapsFailureSamples(t *testing.T) {
	stats := &ScanStats{}
	target := scanpkg.Target{IP: "10.0.0.1", Port: 443}

	for i := 0; i < MaxFailureSamples+5; i++ {
		stats.RecordProbeFailure(target, "fail")
	}
	if len(stats.FailureSamples) != MaxFailureSamples {
		t.Fatalf("samples = %d, want cap %d", len(stats.FailureSamples), MaxFailureSamples)
	}
}

func TestFailureSamplesJSON(t *testing.T) {
	data, err := failureSamplesJSON([]TargetFailureSample{
		{IP: "1.2.3.4", Port: 443, Reason: "timeout", Kind: "probe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded []TargetFailureSample
	scanner := failureSamplesArg(&decoded)
	if err := scanner.Scan(data); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].IP != "1.2.3.4" {
		t.Fatalf("decoded = %#v", decoded)
	}
}
