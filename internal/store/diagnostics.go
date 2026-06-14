package store

import (
	"encoding/json"
	"fmt"

	scanpkg "github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
)

const MaxFailureSamples = 50

// TargetFailureSample is a capped per-target failure record persisted on the scan.
type TargetFailureSample struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Reason   string `json:"reason"`
	Kind     string `json:"kind"` // "probe" or "upsert"
}

// ScanSummary aggregates scan completion stats persisted to the database.
type ScanSummary struct {
	TargetsTotal      int
	TargetsScanned    int
	TargetsSucceeded  int
	TargetsFailed     int
	CertsFound        int
	UpsertFailures    int
	ExpansionWarnings []string
	FailureSamples    []TargetFailureSample
}

// ScanStats tracks in-memory counters during a scan run.
type ScanStats struct {
	Scanned          int
	Succeeded        int
	Failed           int
	CertsFound       int
	UpsertFailures   int
	FailureSamples   []TargetFailureSample
}

func (s *ScanStats) RecordProbeFailure(target scanpkg.Target, reason string) {
	s.Failed++
	s.addSample(target, reason, "probe")
}

func (s *ScanStats) RecordProbeSuccess() {
	s.Succeeded++
}

func (s *ScanStats) RecordUpsertFailure(target scanpkg.Target, reason string) {
	s.UpsertFailures++
	s.addSample(target, reason, "upsert")
}

func (s *ScanStats) RecordCertFound() {
	s.CertsFound++
}

func (s *ScanStats) Summary(targetsTotal int, warnings []string) ScanSummary {
	w := warnings
	if w == nil {
		w = []string{}
	}
	samples := s.FailureSamples
	if samples == nil {
		samples = []TargetFailureSample{}
	}
	return ScanSummary{
		TargetsTotal:      targetsTotal,
		TargetsScanned:    s.Scanned,
		TargetsSucceeded:  s.Succeeded,
		TargetsFailed:     s.Failed,
		CertsFound:        s.CertsFound,
		UpsertFailures:    s.UpsertFailures,
		ExpansionWarnings: w,
		FailureSamples:    samples,
	}
}

func (s *ScanStats) addSample(target scanpkg.Target, reason, kind string) {
	if len(s.FailureSamples) >= MaxFailureSamples {
		return
	}
	sni := target.Hostname
	if sni == "" {
		sni = target.IP
	}
	s.FailureSamples = append(s.FailureSamples, TargetFailureSample{
		IP:       target.IP,
		Port:     target.Port,
		Hostname: target.Hostname,
		SNI:      sni,
		Reason:   reason,
		Kind:     kind,
	})
}

func failureSamplesJSON(samples []TargetFailureSample) ([]byte, error) {
	if samples == nil {
		samples = []TargetFailureSample{}
	}
	return json.Marshal(samples)
}

type failureSamplesScanner struct {
	dest *[]TargetFailureSample
}

func failureSamplesArg(dest *[]TargetFailureSample) failureSamplesScanner {
	if *dest == nil {
		*dest = []TargetFailureSample{}
	}
	return failureSamplesScanner{dest: dest}
}

func (f *failureSamplesScanner) Scan(src any) error {
	if src == nil {
		*f.dest = []TargetFailureSample{}
		return nil
	}
	var data []byte
	switch v := src.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported failure_samples type %T", src)
	}
	if len(data) == 0 {
		*f.dest = []TargetFailureSample{}
		return nil
	}
	return json.Unmarshal(data, f.dest)
}

func targetString(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}
