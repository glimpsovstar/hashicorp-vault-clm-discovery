package governance

import (
	"strings"
)

const (
	ScopeInternal = "internal"
	ScopeExternal = "external"
)

// publicCAHints are substrings matched case-insensitively against issuer DN.
var publicCAHints = []string{
	"let's encrypt",
	"digicert",
	"globalsign",
	"sectigo",
	"comodo",
	"google trust",
	"amazon",
	"entrust",
	"go daddy",
	"godaddy",
	"identrust",
	"starfield",
	"thawte",
	"verisign",
	"geotrust",
	"rapidssl",
	"usertrust",
	"buypass",
	"ssl.com",
	"zerossl",
	"cloudflare",
}

// internalHostnameSuffixes mark hosts served on private/internal networks.
var internalHostnameSuffixes = []string{
	".local",
	".internal",
	".lan",
	".corp",
	".private",
	".home",
}

// ClassifyScope assigns internal vs external scope for v1 discovery.
// Vault reconciliation (v1.1) may override via manual enrichment.
func ClassifyScope(chainStatus, issuerDN, hostname, environment string) string {
	if chainStatus == "self_signed" {
		return ScopeInternal
	}

	host := strings.ToLower(strings.TrimSpace(hostname))
	for _, suffix := range internalHostnameSuffixes {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return ScopeInternal
		}
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ScopeInternal
	}

	issuer := strings.ToLower(issuerDN)
	for _, hint := range publicCAHints {
		if strings.Contains(issuer, hint) {
			return ScopeExternal
		}
	}

	env := strings.ToLower(strings.TrimSpace(environment))
	if env == "dev" || env == "development" || env == "staging" {
		return ScopeInternal
	}

	if strings.Contains(issuer, "vault") || strings.Contains(issuer, "internal ca") {
		return ScopeInternal
	}

	// Default: treat as external/public CA until v1.1 reconciliation enriches.
	return ScopeExternal
}
