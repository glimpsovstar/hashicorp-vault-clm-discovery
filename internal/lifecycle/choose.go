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
// then migrate for unmanaged/imported leaves with a usable chain.
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
	case !in.IsCA && (in.ManagedStatus == "unmanaged" || in.ManagedStatus == "imported") &&
		in.ChainStatus != "incomplete" && in.ChainStatus != "untrusted_root":
		return ChooseResult{
			Code:      "migrate_vault",
			Title:     "Migrate to Vault",
			Rationale: "This leaf is not Vault-issued. Vault will issue a new certificate via AAP; CLM cannot upload the scanned PEM (no private key). Status stays Pending until the new fingerprint is on the wire.",
			CTA:       "Migrate to Vault",
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
