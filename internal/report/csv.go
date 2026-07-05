package report

import (
	"bytes"
	"encoding/csv"
	"strings"
)

// csvHeader is the flattened insight schema; kept stable for downstream parsers.
var csvHeader = []string{
	"category", "type", "severity", "recommendation",
	"subject_cn", "fingerprint_sha256", "issuer_dn",
	"days_until_expiry", "tags", "description",
}

// RenderCSV flattens the report's insight list to CSV. It never emits PEM. All
// cell values pass through sanitizeCSVCell to defend against spreadsheet formula
// injection; encoding/csv handles comma/quote/newline quoting.
func RenderCSV(doc Document) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	if err := w.Write(csvHeader); err != nil {
		return nil, err
	}
	for _, in := range doc.Insights {
		days := ""
		if v, ok := in.Metadata["days_until_expiry"]; ok {
			days = v
		}
		row := []string{
			in.Category,
			in.Type,
			string(in.Severity),
			in.Recommendation,
			in.SubjectCN,
			in.Fingerprint,
			in.IssuerDN,
			days,
			strings.Join(in.Tags, "|"),
			in.Description,
		}
		for i := range row {
			row[i] = sanitizeCSVCell(row[i])
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sanitizeCSVCell neutralizes CSV formula injection: a leading =, +, -, @, TAB,
// or CR can cause spreadsheet apps to execute the cell as a formula. Prefixing
// with a single quote forces text interpretation. Values here originate from
// scanned endpoints (Subject CN, issuer DN), so they are treated as untrusted.
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
