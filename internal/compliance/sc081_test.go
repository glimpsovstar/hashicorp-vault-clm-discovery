package compliance

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEvaluateSC081_ValiditySchedule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		validityDays int
		notBefore   time.Time
		wantRule    string
	}{
		{
			name:         "365d after 2026-03-15 exceeds 199d ceiling",
			validityDays: 365,
			notBefore:    time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			wantRule:     "sc081.validity.199d",
		},
		{
			name:         "180d after 2026-03-15 within ceiling",
			validityDays: 180,
			notBefore:    time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			wantRule:     "",
		},
		{
			name:         "120d after 2027-03-15 exceeds 99d ceiling",
			validityDays: 120,
			notBefore:    time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
			wantRule:     "sc081.validity.99d",
		},
		{
			name:         "64d after 2028-03-15 within ceiling",
			validityDays: 64,
			notBefore:    time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC),
			wantRule:     "",
		},
		{
			name:         "65d after 2028-03-15 exceeds 64d ceiling",
			validityDays: 65,
			notBefore:    time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC),
			wantRule:     "sc081.validity.64d",
		},
		{
			name:         "48d after 2029-03-15 exceeds 47d ceiling",
			validityDays: 48,
			notBefore:    time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC),
			wantRule:     "sc081.validity.47d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := CertInput{
				ID:          uuid.New(),
				Fingerprint: "fp",
				SubjectCN:   "example.com",
				NotBefore:   tt.notBefore,
				NotAfter:    tt.notBefore.AddDate(0, 0, tt.validityDays),
				CertScope:   "external",
			}

			findings := EvaluateSC081(cert)
			got := ruleIDForPack(findings, "sc081.validity")

			if got != tt.wantRule {
				t.Fatalf("validity rule = %q, want %q (findings: %+v)", got, tt.wantRule, findings)
			}
			if tt.wantRule != "" {
				for _, f := range findings {
					if f.RuleID == tt.wantRule && f.Severity != "critical" {
						t.Fatalf("severity = %q, want critical", f.Severity)
					}
				}
			}
		})
	}
}

func TestEvaluateSC081_ExpirySeverity(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()

	tests := []struct {
		name      string
		scope     string
		env       *string
		daysLeft  int
		wantRule  string
		wantSev   string
	}{
		{
			name:     "external critical within 14 days",
			scope:    "external",
			daysLeft: 10,
			wantRule: "sc081.expiry.critical",
			wantSev:  "critical",
		},
		{
			name:     "external warning within 60 days",
			scope:    "external",
			daysLeft: 45,
			wantRule: "sc081.expiry.warning",
			wantSev:  "warning",
		},
		{
			name:     "internal info within 14 days",
			scope:    "internal",
			daysLeft: 10,
			wantRule: "sc081.expiry.critical",
			wantSev:  "info",
		},
		{
			name:     "internal prod critical within 14 days",
			scope:    "internal",
			env:      strPtr("prod"),
			daysLeft: 10,
			wantRule: "sc081.expiry.critical",
			wantSev:  "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cert := CertInput{
				ID:              uuid.New(),
				Fingerprint:     "fp",
				SubjectCN:       "example.com",
				NotBefore:       now.AddDate(0, -3, 0),
				NotAfter:        now.AddDate(0, 0, tt.daysLeft),
				CertScope:       tt.scope,
				Environment:     tt.env,
				DaysUntilExpiry: tt.daysLeft,
			}

			findings := EvaluateSC081(cert)
			var got *Finding
			for i := range findings {
				if findings[i].RuleID == tt.wantRule {
					got = &findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("missing rule %q in %+v", tt.wantRule, findings)
			}
			if got.Severity != tt.wantSev {
				t.Fatalf("severity = %q, want %q", got.Severity, tt.wantSev)
			}
		})
	}
}

func ruleIDForPack(findings []Finding, prefix string) string {
	for _, f := range findings {
		if len(f.RuleID) >= len(prefix) && f.RuleID[:len(prefix)] == prefix {
			return f.RuleID
		}
	}
	return ""
}

func strPtr(s string) *string { return &s }
