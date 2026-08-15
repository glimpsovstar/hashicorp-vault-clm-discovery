package compliance

// Five-level severities used at the finding/UI boundary. Packs may still emit
// "warning"; MapPackSeverity converts once at persist so the UI never sees it.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
	SeverityWarning  = "warning" // pack-only; never stored
)

// Numeric scores for risk_score = max(non-waived). Bands: critical ≥80, high ≥60,
// medium ≥40, low ≥20, info below that.
const (
	ScoreCritical = 90
	ScoreHigh     = 70
	ScoreMedium   = 40
	ScoreLow      = 20
	ScoreInfo     = 5
)

// MapPackSeverity maps a pack-emitted severity into the 5-level UI scale.
// PCI hygiene warnings become medium; other pack warnings become high.
func MapPackSeverity(pack, severity string) string {
	switch severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return severity
	case SeverityWarning:
		if pack == "pci" {
			return SeverityMedium
		}
		return SeverityHigh
	default:
		return SeverityInfo
	}
}

// ScoreSeverity returns the numeric contribution of a 5-level severity.
func ScoreSeverity(severity string) int {
	switch severity {
	case SeverityCritical:
		return ScoreCritical
	case SeverityHigh:
		return ScoreHigh
	case SeverityMedium:
		return ScoreMedium
	case SeverityLow:
		return ScoreLow
	case SeverityInfo:
		return ScoreInfo
	default:
		return 0
	}
}

// MapFindingForPersist returns a copy of f with severity mapped for storage.
func MapFindingForPersist(f Finding) Finding {
	out := f
	out.Severity = MapPackSeverity(f.Pack, f.Severity)
	return out
}
