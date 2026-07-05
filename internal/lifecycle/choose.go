package lifecycle

// ChooseInput carries the discovered signals used to recommend a Choose-phase
// action. It deliberately uses primitives (not store types) so this package
// stays free of a store import cycle.
type ChooseInput struct {
	CertScope     string // internal | external
	ManagedStatus string // unmanaged | managed_in_vault | imported
	ChainStatus   string // complete | incomplete | self_signed | untrusted_root
	IsCA          bool
}

// ChooseResult is the recommended next lifecycle action for a certificate.
type ChooseResult struct {
	Code      string `json:"code"`
	Title     string `json:"title"`
	Rationale string `json:"rationale"`
	CTA       string `json:"cta"`
}

// ChooseRecommendation maps a certificate's signals to a single recommended
// Choose-phase action, following the lifecycle decision tree. Order matters:
// already-managed short-circuits, then trust (chain) problems, then CA import,
// then the CLM-catalog (imported) state, then scope-based routing. A self_signed
// chain is not treated as a trust problem here — an unmanaged self-signed
// internal leaf is plausibly Vault-issued and routes to reconcile.
func ChooseRecommendation(in ChooseInput) ChooseResult {
	switch {
	case in.ManagedStatus == "managed_in_vault":
		return ChooseResult{
			Code:      "already_managed",
			Title:     "Managed by Vault",
			Rationale: "This certificate is already matched to Vault PKI by reconcile; no Choose action is needed.",
			CTA:       "None",
		}
	case in.ChainStatus == "incomplete" || in.ChainStatus == "untrusted_root":
		return ChooseResult{
			Code:      "fix_chain",
			Title:     "Complete the trust chain",
			Rationale: "The presented chain is incomplete or terminates in an untrusted root. Import the intermediate/root CA, then rescan.",
			CTA:       "Import CA to Vault, then rescan",
		}
	case in.IsCA && in.ManagedStatus == "unmanaged":
		return ChooseResult{
			Code:      "import_ca",
			Title:     "Import CA into Vault",
			Rationale: "This CA is on the wire but not in Vault PKI. Import the bundle so Vault can manage issuance from it.",
			CTA:       "Import CA to Vault",
		}
	case in.ManagedStatus == "imported":
		return ChooseResult{
			Code:      "catalog_tracked",
			Title:     "Tracked in CLM",
			Rationale: "This certificate is tracked in the CLM catalog. Run Vault reconcile to confirm whether Vault also manages it.",
			CTA:       "Reconcile with Vault",
		}
	case in.CertScope == "internal":
		return ChooseResult{
			Code:      "reconcile_vault",
			Title:     "Reconcile with Vault",
			Rationale: "An internal certificate that is not yet matched is likely Vault-issued. Run reconcile to confirm management.",
			CTA:       "Reconcile with Vault",
		}
	default:
		return ChooseResult{
			Code:      "monitor_external",
			Title:     "Track as external",
			Rationale: "This looks like a public-CA certificate. Track it in CLM for visibility, or leave it managed by its public CA.",
			CTA:       "Track in CLM",
		}
	}
}
