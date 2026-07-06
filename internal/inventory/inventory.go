// Package inventory renders CLM's renewable certificates as an Ansible dynamic
// inventory. AAP pulls this (a URL/script inventory source) instead of querying
// Vault directly, making CLM the source of truth for renewal targets (ADR 0001).
package inventory

import "github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"

// Build renders the Ansible dynamic-inventory "--list" JSON document from
// certificates that carry renewal config. Each host is keyed by the certificate
// CN; hostvars carry the vault-ansible-clm issue-role variables plus CLM
// metadata. Hosts are grouped under "clm_renewable" and, when a service is set,
// under "svc_<service>". Certificates without renewal config or CN are skipped;
// duplicate CNs keep the first occurrence.
func Build(certs []store.Certificate) map[string]any {
	hostvars := map[string]any{}
	renewable := []string{}
	svcGroups := map[string][]string{}
	seen := map[string]bool{}

	for _, c := range certs {
		if c.RenewalConfig == nil {
			continue
		}
		cn := ""
		if c.SubjectCN != nil {
			cn = *c.SubjectCN
		}
		if cn == "" || seen[cn] {
			continue
		}
		seen[cn] = true
		cfg := c.RenewalConfig

		vars := map[string]any{
			"cert_common_name_override": cn,
			"vault_pki_mount":           cfg.Mount,
			"vault_pki_role":            cfg.Role,
			"clm_certificate_id":        c.ID.String(),
			"clm_days_until_expiry":     c.DaysUntilExpiry,
		}
		if cfg.Service != "" {
			vars["cert_service_type"] = cfg.Service
		}
		if cfg.TargetHosts != "" {
			vars["clm_target_hosts"] = cfg.TargetHosts
		}
		if cfg.TTL != "" {
			vars["vault_cert_ttl"] = cfg.TTL
		}
		if cfg.AltNames != "" {
			vars["cert_alt_names_override"] = cfg.AltNames
		}

		hostvars[cn] = vars
		renewable = append(renewable, cn)
		if cfg.Service != "" {
			g := "svc_" + cfg.Service
			svcGroups[g] = append(svcGroups[g], cn)
		}
	}

	doc := map[string]any{
		"_meta":         map[string]any{"hostvars": hostvars},
		"clm_renewable": map[string]any{"hosts": renewable},
	}
	children := []string{"clm_renewable"}
	for g, hosts := range svcGroups {
		doc[g] = map[string]any{"hosts": hosts}
		children = append(children, g)
	}
	doc["all"] = map[string]any{"children": children}
	return doc
}
