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
