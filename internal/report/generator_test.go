package report

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/compliance"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func TestRenderMarkdown_ContainsRequiredSections(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	finished := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	scan := store.Scan{
		ID:               scanID,
		Status:           "completed",
		Hostnames:        []string{"demo.example.com"},
		Ports:            []int{443},
		TargetsTotal:     1,
		TargetsSucceeded: 1,
		CertsFound:       3,
		FinishedAt:       &finished,
		CreatedAt:        finished,
	}

	doc := Generate(GenerateInput{
		Scan: scan,
		BlindSpot: BlindSpotSummary{
			VaultManaged:    1,
			Discovered:      3,
			Shadow:          2,
			SC081Violations: 1,
		},
		Compliance: compliance.ComplianceSummary{
			ScanID:              scanID,
			TotalCerts:          3,
			SC081ViolationCount: 1,
			PCIFindingCount:     1,
			FindingsBySeverity:  map[string]int{"critical": 1},
			FindingsByPack:      map[string]int{"sc081": 1, "pci": 1},
			AlgorithmInventory: compliance.AlgorithmInventory{
				RSA2048Plus: 2,
				RSAUnder2048: 1,
			},
			Findings: []compliance.Finding{
				{
					RuleID:      "sc081.validity.199d",
					Pack:        "sc081",
					Severity:    "critical",
					Title:       "Validity exceeds 199 days",
					Fingerprint: "abc123def456",
					SubjectCN:   "long.example.com",
				},
				{
					RuleID:   "pci.owner.missing",
					Pack:     "pci",
					Severity: "warning",
					Title:    "Missing owner",
				},
			},
		},
	})

	md := RenderMarkdown(doc)

	required := []string{
		"# Executive summary",
		"## Blind-spot reveal",
		"## SC-081 posture",
		"## PCI inventory gaps",
		"## Algorithm inventory",
		"## Scan diagnostics",
	}
	for _, section := range required {
		if !strings.Contains(md, section) {
			t.Fatalf("markdown missing section %q\n%s", section, md)
		}
	}
}

func TestRenderMarkdown_NoFullPEM(t *testing.T) {
	t.Parallel()

	pem := "-----BEGIN CERTIFICATE-----\nMIIBfakePEMdata\n-----END CERTIFICATE-----"
	scan := store.Scan{ID: uuid.New(), Status: "completed"}
	doc := Generate(GenerateInput{
		Scan:      scan,
		BlindSpot: BlindSpotSummary{},
		Compliance: compliance.ComplianceSummary{
			Findings: []compliance.Finding{
				{
					Fingerprint: "fp1",
					SubjectCN:   "test.example.com",
					Detail:      pem,
				},
			},
		},
	})

	md := RenderMarkdown(doc)
	if strings.Contains(md, "BEGIN CERTIFICATE") {
		t.Fatalf("markdown must not contain PEM body")
	}
}

func TestRenderMarkdown_EscapesTableCells(t *testing.T) {
	t.Parallel()

	// A scanned endpoint controls its own certificate Subject CN, so it must
	// not be able to break out of / inject into the markdown findings table.
	maliciousCN := "evil | row\n# Injected heading"
	scan := store.Scan{ID: uuid.New(), Status: "completed"}
	doc := Generate(GenerateInput{
		Scan:      scan,
		BlindSpot: BlindSpotSummary{},
		Compliance: compliance.ComplianceSummary{
			Findings: []compliance.Finding{
				{
					RuleID:      "sc081.validity.199d",
					Pack:        "sc081",
					Severity:    "critical",
					Fingerprint: "abc123def456",
					SubjectCN:   maliciousCN,
				},
			},
		},
	})

	md := RenderMarkdown(doc)

	if !strings.Contains(md, `evil \| row`) {
		t.Fatalf("pipe in Subject CN must be escaped as \\|\n%s", md)
	}
	if strings.Contains(md, "\n# Injected heading") {
		t.Fatalf("newline in Subject CN must be neutralized so it cannot inject a heading/row\n%s", md)
	}
}

func TestEscapeCell(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "pipe", in: `a|b`, want: `a\|b`},
		{name: "newline collapses", in: "a\nb", want: "a b"},
		{name: "carriage return collapses", in: "a\rb", want: "a b"},
		// Backslash must be escaped first, else `\|` renders as literal backslash
		// plus a live column separator (injection bypass).
		{name: "backslash before pipe", in: `\|`, want: `\\\|`},
		{name: "lone backslash", in: `\`, want: `\\`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := escapeCell(tt.in); got != tt.want {
				t.Fatalf("escapeCell(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRenderJSON_Structure(t *testing.T) {
	t.Parallel()

	scanID := uuid.New()
	doc := Generate(GenerateInput{
		Scan: store.Scan{ID: scanID, Status: "completed"},
		BlindSpot: BlindSpotSummary{
			VaultManaged: 2,
			Discovered:   5,
			Shadow:       3,
		},
		Compliance: compliance.ComplianceSummary{ScanID: scanID, TotalCerts: 5},
	})

	raw, err := RenderJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, key := range []string{`"report_version"`, `"scan_id"`, `"blind_spot"`, `"compliance"`, `"scan_diagnostics"`} {
		if !strings.Contains(body, key) {
			t.Fatalf("json missing %q: %s", key, body)
		}
	}
}
