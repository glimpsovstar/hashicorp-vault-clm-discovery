package report

import (
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

const ReportVersion = "0.1.0"

// BlindSpotSummary is the Vault vs wire comparison for a scan report.
type BlindSpotSummary struct {
	VaultManaged    int `json:"vault_managed"`
	Discovered      int `json:"discovered"`
	Shadow          int `json:"shadow"`
	SC081Violations int `json:"sc081_violations"`
}

// ScanDiagnostics captures probe and persistence metrics from a scan run.
type ScanDiagnostics struct {
	TargetsTotal      int                           `json:"targets_total"`
	TargetsSucceeded  int                           `json:"targets_succeeded"`
	TargetsFailed     int                           `json:"targets_failed"`
	CertsFound        int                           `json:"certs_found"`
	UpsertFailures    int                           `json:"upsert_failures"`
	ExpansionWarnings []string                      `json:"expansion_warnings,omitempty"`
	FailureSamples    []store.TargetFailureSample   `json:"failure_samples,omitempty"`
	Error             *string                       `json:"error,omitempty"`
}

// Document is the structured scan report payload shared by renderers.
type Document struct {
	ReportVersion string                      `json:"report_version"`
	GeneratedAt   time.Time                   `json:"generated_at"`
	ScanID        uuid.UUID                   `json:"scan_id"`
	ScanStatus    string                      `json:"scan_status"`
	Scope         ScopeSummary                `json:"scope"`
	BlindSpot     BlindSpotSummary            `json:"blind_spot"`
	Compliance    compliance.ComplianceSummary `json:"compliance"`
	Diagnostics   ScanDiagnostics             `json:"scan_diagnostics"`
}

// ScopeSummary describes scan targets for the report header.
type ScopeSummary struct {
	CIDRs       []string   `json:"cidrs"`
	Hostnames   []string   `json:"hostnames"`
	Ports       []int      `json:"ports"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// GenerateInput aggregates data sources for report generation.
type GenerateInput struct {
	Scan       store.Scan
	BlindSpot  BlindSpotSummary
	Compliance compliance.ComplianceSummary
}

// Generate builds a report document from scan, blind-spot, and compliance data.
func Generate(in GenerateInput) Document {
	return Document{
		ReportVersion: ReportVersion,
		GeneratedAt:   time.Now().UTC(),
		ScanID:        in.Scan.ID,
		ScanStatus:    in.Scan.Status,
		Scope: ScopeSummary{
			CIDRs:      in.Scan.CIDRs,
			Hostnames:  in.Scan.Hostnames,
			Ports:      in.Scan.Ports,
			StartedAt:  in.Scan.StartedAt,
			FinishedAt: in.Scan.FinishedAt,
		},
		BlindSpot:  in.BlindSpot,
		Compliance: in.Compliance,
		Diagnostics: ScanDiagnostics{
			TargetsTotal:      in.Scan.TargetsTotal,
			TargetsSucceeded:  in.Scan.TargetsSucceeded,
			TargetsFailed:     in.Scan.TargetsFailed,
			CertsFound:        in.Scan.CertsFound,
			UpsertFailures:    in.Scan.UpsertFailures,
			ExpansionWarnings: in.Scan.ExpansionWarnings,
			FailureSamples:    in.Scan.FailureSamples,
			Error:             in.Scan.Error,
		},
	}
}

// BuildBlindSpotSummary computes shadow count from managed and discovered totals.
func BuildBlindSpotSummary(managed, discovered, sc081Violations int) BlindSpotSummary {
	shadow := discovered - managed
	if shadow < 0 {
		shadow = 0
	}
	return BlindSpotSummary{
		VaultManaged:    managed,
		Discovered:      discovered,
		Shadow:          shadow,
		SC081Violations: sc081Violations,
	}
}
