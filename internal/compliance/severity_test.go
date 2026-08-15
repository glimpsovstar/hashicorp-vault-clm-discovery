package compliance

import "testing"

func TestMapPackSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pack, sev, want string
	}{
		{"sc081", "critical", "critical"},
		{"sc081", "warning", "high"},
		{"sc081", "info", "info"},
		{"pci", "warning", "medium"},
		{"pci", "info", "info"},
		{"crypto", "warning", "high"},
		{"ops", "high", "high"},
		{"ops", "low", "low"},
		{"ops", "mystery", "info"},
	}
	for _, tc := range cases {
		got := MapPackSeverity(tc.pack, tc.sev)
		if got != tc.want {
			t.Errorf("MapPackSeverity(%q,%q)=%q want %q", tc.pack, tc.sev, got, tc.want)
		}
	}
}

func TestScoreSeverity_CriticalBand(t *testing.T) {
	t.Parallel()
	if ScoreSeverity("critical") < 80 {
		t.Fatalf("critical score %d not in critical band (≥80)", ScoreSeverity("critical"))
	}
	if ScoreSeverity("high") < 60 || ScoreSeverity("high") >= 80 {
		t.Fatalf("high score %d not in high band", ScoreSeverity("high"))
	}
}

func TestMapFindingForPersist_NeverStoresWarning(t *testing.T) {
	t.Parallel()
	f := MapFindingForPersist(Finding{Pack: "sc081", Severity: "warning", RuleID: "sc081.expiry.warning"})
	if f.Severity == "warning" {
		t.Fatal("persisted finding must not keep pack warning severity")
	}
	if f.Severity != "high" {
		t.Fatalf("severity=%q want high", f.Severity)
	}
}
