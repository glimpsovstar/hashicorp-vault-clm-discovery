package report

import (
	"encoding/csv"
	"strings"
	"testing"
)

func TestRenderCSV_HeaderAndRows(t *testing.T) {
	t.Parallel()

	doc := Document{
		Insights: []Insight{
			{Category: "certificate", Type: "expired", Severity: SeverityHigh, Recommendation: RecPlanRenewal, SubjectCN: "a.example.com", Description: "expired"},
			{Category: "certificate", Type: "san_mismatch", Severity: SeverityLow, Recommendation: RecFixSAN, SubjectCN: "b.example.com", Description: "mismatch"},
		},
	}

	raw, err := RenderCSV(doc)
	if err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(records) != 3 { // header + 2 rows
		t.Fatalf("records = %d, want 3", len(records))
	}
	if records[0][0] != "category" {
		t.Fatalf("first header = %q, want category", records[0][0])
	}
	if records[1][4] != "a.example.com" {
		t.Fatalf("row1 subject_cn = %q, want a.example.com", records[1][4])
	}
}

func TestRenderCSV_QuotesCommaAndEscapesFormula(t *testing.T) {
	t.Parallel()

	doc := Document{
		Insights: []Insight{
			{Category: "certificate", Type: "expired", Severity: SeverityHigh, SubjectCN: "CN=with,comma", Description: "=SUM(A1:A2)"},
		},
	}

	raw, err := RenderCSV(doc)
	if err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	// encoding/csv must round-trip the comma-bearing field intact.
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if records[1][4] != "CN=with,comma" {
		t.Fatalf("subject_cn = %q, want CN=with,comma", records[1][4])
	}
	// Formula-injection guard prefixes the leading '=' with a single quote.
	if records[1][9] != "'=SUM(A1:A2)" {
		t.Fatalf("description = %q, want formula-escaped with leading quote", records[1][9])
	}
}

func TestSanitizeCSVCell(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"safe", "safe"},
		{"=cmd", "'=cmd"},
		{"+1", "'+1"},
		{"-1", "'-1"},
		{"@x", "'@x"},
		{"\tcmd", "'\tcmd"},
		{"\rcmd", "'\rcmd"},
	} {
		if got := sanitizeCSVCell(tc.in); got != tc.want {
			t.Fatalf("sanitizeCSVCell(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
