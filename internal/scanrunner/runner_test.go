package scanrunner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

type recordingStore struct {
	failScanCalled bool
	failScanMsg    string
	runningTotal   int
	summary        store.ScanSummary
	updateRunning  error
}

func (s *recordingStore) UpdateScanRunning(_ context.Context, _ uuid.UUID, targetsTotal int) error {
	if s.updateRunning != nil {
		return s.updateRunning
	}
	s.runningTotal = targetsTotal
	return nil
}

func (s *recordingStore) UpdateScanProgress(context.Context, uuid.UUID, int, int) error {
	return nil
}

func (s *recordingStore) CompleteScan(_ context.Context, _ uuid.UUID, summary store.ScanSummary) error {
	s.summary = summary
	return nil
}

func (s *recordingStore) FailScan(_ context.Context, _ uuid.UUID, errMsg string) error {
	s.failScanCalled = true
	s.failScanMsg = errMsg
	return nil
}

func (s *recordingStore) UpsertCertificate(context.Context, uuid.UUID, cert.ParsedCertificate, cert.Observation) (uuid.UUID, error) {
	return uuid.New(), nil
}

func (s *recordingStore) UpsertIssuer(context.Context, cert.ParsedCertificate, []string) error {
	return nil
}

type stubProber struct {
	err error
}

func (p stubProber) Probe(_ context.Context, target scanner.Target) scanner.ProbeResult {
	return scanner.ProbeResult{Target: target, Error: p.err}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunFailsWhenExpansionFails(t *testing.T) {
	st := &recordingStore{}
	runner := New(st, stubProber{err: errors.New("probe fail")}, testLogger(), "info", true)

	err := runner.Run(context.Background(), Job{
		ScanID: uuid.New(),
		Ports:  []int{443},
	})
	if err == nil {
		t.Fatal("expected expansion error")
	}
	if !st.failScanCalled {
		t.Fatal("expected FailScan to be called")
	}
	if !strings.Contains(st.failScanMsg, "no scan targets") {
		t.Fatalf("unexpected fail message: %q", st.failScanMsg)
	}
}

func TestRunCompletesWithProbeFailures(t *testing.T) {
	st := &recordingStore{}
	runner := New(st, stubProber{err: errors.New("timeout")}, testLogger(), "info", true)

	err := runner.Run(context.Background(), Job{
		ScanID:      uuid.New(),
		CIDRs:       []string{"127.0.0.1/32"},
		Ports:       []int{443},
		Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.runningTotal != 1 {
		t.Fatalf("runningTotal = %d, want 1", st.runningTotal)
	}
	if st.summary.TargetsTotal != 1 {
		t.Fatalf("targets_total = %d, want 1", st.summary.TargetsTotal)
	}
	if st.summary.TargetsFailed != 1 {
		t.Fatalf("targets_failed = %d, want 1", st.summary.TargetsFailed)
	}
	if st.summary.TargetsSucceeded != 0 {
		t.Fatalf("targets_succeeded = %d, want 0", st.summary.TargetsSucceeded)
	}
}

func TestRunCompleteScanIncludesExpansionWarnings(t *testing.T) {
	st := &recordingStore{}
	runner := New(st, stubProber{err: errors.New("timeout")}, testLogger(), "info", true)

	err := runner.Run(context.Background(), Job{
		ScanID:      uuid.New(),
		CIDRs:       []string{"127.0.0.1/32"},
		Hostnames:   []string{"aap.david-joo.sbx.hashicorp.io.invalid"},
		Ports:       []int{443},
		Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.summary.ExpansionWarnings) != 1 {
		t.Fatalf("expansion_warnings = %#v, want 1 entry", st.summary.ExpansionWarnings)
	}
	if !strings.Contains(st.summary.ExpansionWarnings[0], "hashicorp.io.invalid") {
		t.Fatalf("unexpected warning: %q", st.summary.ExpansionWarnings[0])
	}
}

func TestRunFailsWhenUpdateScanRunningFails(t *testing.T) {
	st := &recordingStore{updateRunning: errors.New("db unavailable")}
	runner := New(st, stubProber{}, testLogger(), "info", true)

	err := runner.Run(context.Background(), Job{
		ScanID: uuid.New(),
		CIDRs:  []string{"127.0.0.1/32"},
		Ports:  []int{443},
	})
	if err == nil {
		t.Fatal("expected UpdateScanRunning error")
	}
	if !st.failScanCalled {
		t.Fatal("expected FailScan to be called")
	}
}

func TestTargetAttrsIncludesHostnameAndCert(t *testing.T) {
	parsed := &cert.ParsedCertificate{
		FingerprintSHA256: "abc123",
		SerialNumber:      "1",
	}
	attrs := targetAttrs(scanner.Target{
		IP:       "203.0.113.1",
		Port:     443,
		Hostname: "example.com",
	}, "example.com", parsed)

	m := attrsToMap(attrs)
	if m["hostname"] != "example.com" {
		t.Fatalf("hostname = %v", m["hostname"])
	}
	if m["fingerprint_sha256"] != "abc123" {
		t.Fatalf("fingerprint = %v", m["fingerprint_sha256"])
	}
}

func TestCertAttrs(t *testing.T) {
	attrs := certAttrs(&cert.ParsedCertificate{
		FingerprintSHA256: "deadbeef",
		SerialNumber:      "42",
	})
	m := attrsToMap(attrs)
	if m["serial_number"] != "42" {
		t.Fatalf("serial_number = %v", m["serial_number"])
	}
}

func attrsToMap(attrs []any) map[string]any {
	out := make(map[string]any, len(attrs)/2)
	for i := 0; i+1 < len(attrs); i += 2 {
		key, ok := attrs[i].(string)
		if !ok {
			continue
		}
		out[key] = attrs[i+1]
	}
	return out
}
