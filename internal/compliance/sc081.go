package compliance

import (
	"fmt"
	"math"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/governance"
)

type sc081Ceiling struct {
	effective time.Time
	maxDays   int
	ruleID    string
}

var sc081Ceilings = []sc081Ceiling{
	{effective: time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), maxDays: 47, ruleID: "sc081.validity.47d"},
	{effective: time.Date(2028, 3, 15, 0, 0, 0, 0, time.UTC), maxDays: 64, ruleID: "sc081.validity.64d"},
	{effective: time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), maxDays: 99, ruleID: "sc081.validity.99d"},
	{effective: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), maxDays: 199, ruleID: "sc081.validity.199d"},
}

// EvaluateSC081 returns SC-081v3 findings for a certificate.
func EvaluateSC081(cert CertInput) []Finding {
	var findings []Finding

	if f := sc081ValidityFinding(cert); f != nil {
		findings = append(findings, *f)
	}
	if f := sc081ExpiryFinding(cert); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

func sc081ValidityFinding(cert CertInput) *Finding {
	ceiling := sc081CeilingFor(cert.NotBefore)
	if ceiling == nil {
		return nil
	}

	maxValidity := time.Duration(ceiling.maxDays) * 24 * time.Hour
	if cert.NotAfter.Sub(cert.NotBefore) <= maxValidity {
		return nil
	}
	validityDays := validityDays(cert.NotBefore, cert.NotAfter)

	return &Finding{
		RuleID:      ceiling.ruleID,
		Pack:        "sc081",
		Severity:    "critical",
		Title:       "SC-081 issued validity exceeds ceiling",
		Detail:      fmt.Sprintf("Certificate issued with %d-day validity; SC-081 ceiling is %d days from %s", validityDays, ceiling.maxDays, ceiling.effective.Format("2006-01-02")),
		CertID:      cert.ID,
		Fingerprint: cert.Fingerprint,
		SubjectCN:   cert.SubjectCN,
	}
}

func sc081ExpiryFinding(cert CertInput) *Finding {
	return sc081ExpiryFindingAt(cert, time.Now().UTC())
}

// sc081ExpiryFindingAt evaluates expiry against a caller-supplied clock so the
// finding reflects the certificate's live NotAfter at evaluation time, not a
// day count frozen at scan time. Expiry is keyed off the NotAfter timestamp
// (not a truncated day count) so a certificate that expired within the last day
// is reported as expired rather than "expires in 0 days".
func sc081ExpiryFindingAt(cert CertInput, now time.Time) *Finding {
	var ruleID, title, detail string
	var baseSeverity string
	switch {
	case cert.NotAfter.Before(now):
		daysAgo := int(now.Sub(cert.NotAfter).Hours() / 24)
		ruleID = "sc081.expiry.expired"
		title = "Certificate has expired"
		detail = fmt.Sprintf("Certificate expired %d day(s) ago", daysAgo)
		baseSeverity = "critical"
	default:
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		switch {
		case days <= 14:
			ruleID = "sc081.expiry.critical"
			title = "Certificate expires within 14 days"
			detail = fmt.Sprintf("Certificate expires in %d days", days)
			baseSeverity = "critical"
		case days <= 60:
			ruleID = "sc081.expiry.warning"
			title = "Certificate expires within 60 days"
			detail = fmt.Sprintf("Certificate expires in %d days", days)
			baseSeverity = "warning"
		default:
			return nil
		}
	}

	severity := sc081ExpirySeverity(cert, baseSeverity)
	return &Finding{
		RuleID:      ruleID,
		Pack:        "sc081",
		Severity:    severity,
		Title:       title,
		Detail:      detail,
		CertID:      cert.ID,
		Fingerprint: cert.Fingerprint,
		SubjectCN:   cert.SubjectCN,
	}
}

func sc081ExpirySeverity(cert CertInput, base string) string {
	if cert.CertScope == governance.ScopeInternal && !isProd(cert.Environment) {
		return "info"
	}
	return base
}

func sc081CeilingFor(notBefore time.Time) *sc081Ceiling {
	nb := notBefore.UTC()
	for _, c := range sc081Ceilings {
		if !nb.Before(c.effective) {
			return &c
		}
	}
	return nil
}

func validityDays(notBefore, notAfter time.Time) int {
	// Round up so a certificate whose validity exceeds a whole-day ceiling by
	// any fraction is reported (and counted) as exceeding it, never truncated
	// back down to the compliant boundary.
	return int(math.Ceil(notAfter.Sub(notBefore).Hours() / 24))
}

func isProd(env *string) bool {
	return env != nil && *env == "prod"
}
