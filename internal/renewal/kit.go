// Package renewal generates the reissue-and-deploy artifacts for the lifecycle
// "Mode C" step. CLM does not issue or deploy certificates itself (Vault PKI
// issues; vault-agent/AAP deploy); this package produces the operator-runnable
// artifacts, and CLM verifies the result via a later rescan + reconcile.
package renewal

import (
	"fmt"
	"regexp"
	"strings"
)

// Target is the deploy mechanism the kit is generated for.
type Target string

const (
	TargetAgent Target = "agent" // HashiCorp Vault Agent
	TargetAAP   Target = "aap"   // Ansible Automation Platform
)

// KitInput describes the certificate and Vault PKI role to reissue from.
type KitInput struct {
	CommonName string // requested leaf CN (defaults handled by caller)
	Mount      string // Vault PKI mount, e.g. "pki"
	Role       string // Vault PKI role, e.g. "web-server"
	Service    string // optional service to reload after renewal
}

// Artifact is a single generated file (content + hint for rendering).
type Artifact struct {
	Filename string `json:"filename"`
	Language string `json:"language"` // hcl | yaml
	Content  string `json:"content"`
}

// Generate renders the renewal kit for the given target. It embeds no secrets:
// Vault Agent uses auto-auth and the AAP playbook uses a Vault lookup, so the
// artifacts are safe to store and share.
func Generate(target Target, in KitInput) ([]Artifact, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	switch target {
	case TargetAgent:
		return []Artifact{agentHCL(in)}, nil
	case TargetAAP:
		return []Artifact{aapPlaybook(in)}, nil
	default:
		return nil, fmt.Errorf("unsupported target %q (want agent|aap)", target)
	}
}

func validate(in KitInput) error {
	if !validName(in.Mount) {
		return fmt.Errorf("invalid mount")
	}
	if !validName(in.Role) {
		return fmt.Errorf("invalid role")
	}
	if !validCommonName(in.CommonName) {
		return fmt.Errorf("invalid common name")
	}
	return nil
}

// Validate reports whether the kit input is safe to use (CN is a DNS hostname,
// mount and role are safe Vault path segments). Exported so the AAP renew
// orchestrator reuses the exact same checks before launching a job.
func Validate(in KitInput) error { return validate(in) }

// ValidService reports whether an optional service name is safe. An empty
// service is allowed (it just means "no service override").
func ValidService(s string) bool { return s == "" || validName(s) }

// ValidReason reports whether a revoke reason is safe for AAP extra_vars
// (no Jinja/SSTI). Empty is invalid — callers require an explicit reason.
func ValidReason(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return false
	}
	if strings.Contains(s, "{{") || strings.Contains(s, "}}") || strings.Contains(s, "{%") {
		return false
	}
	for _, c := range s {
		ok := c == '-' || c == '_' || c == ' ' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

var ttlPattern = regexp.MustCompile(`^[0-9]+(s|m|h|d)$`)

// ValidTTL reports whether s is empty or a Vault-style duration (e.g. "72h",
// "30m", "10d"). Values flow into AAP extra_vars, which Ansible Jinja2-evaluates,
// so an unvalidated value like "{{ lookup('pipe','id') }}" would be template
// injection — this restricts it to a digits+unit duration.
func ValidTTL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	return ttlPattern.MatchString(s)
}

// ValidAltNames reports whether a comma- or space-separated SAN list is safe:
// empty is allowed, otherwise every entry must be a DNS hostname. Same SSTI
// rationale as ValidTTL — these become cert_alt_names_override in AAP.
func ValidAltNames(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !validCommonName(strings.TrimSpace(f)) {
			return false
		}
	}
	return true
}

// validCommonName restricts the CN to a DNS hostname (optionally a single leading
// wildcard label). The CN originates from the scanned certificate's subject_cn
// (attacker-controlled), so this prevents newline/quote/`}}` injection into the
// generated vault-agent HCL / AAP YAML and path traversal in file destinations.
func validCommonName(cn string) bool {
	cn = strings.TrimSpace(cn)
	if cn == "" || len(cn) > 253 || strings.Contains(cn, "..") {
		return false
	}
	body := strings.TrimPrefix(cn, "*.")
	if body == "" || strings.HasPrefix(body, ".") || strings.HasSuffix(body, ".") {
		return false
	}
	for _, c := range body {
		ok := c == '.' || c == '-' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// fileSafe renders a CN safe for a filesystem path (wildcard -> "wildcard").
func fileSafe(cn string) string {
	return strings.ReplaceAll(cn, "*", "wildcard")
}

// validName allows a simple Vault path/role segment; rejects anything that could
// break out of the templated path.
func validName(s string) bool {
	if s == "" || strings.Contains(s, "..") || strings.HasPrefix(s, "/") {
		return false
	}
	for _, c := range s {
		ok := c == '-' || c == '_' || c == '/' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func reloadLine(service, indent string) string {
	if strings.TrimSpace(service) == "" {
		return ""
	}
	return indent + "command = \"systemctl reload " + service + "\"\n"
}

func agentHCL(in KitInput) Artifact {
	var b strings.Builder
	b.WriteString("# Vault Agent renewal for " + in.CommonName + "\n")
	b.WriteString("# Auto-auth (AppRole shown; swap for k8s/jwt as appropriate).\n")
	b.WriteString("auto_auth {\n")
	b.WriteString("  method \"approle\" {\n")
	b.WriteString("    config = {\n")
	b.WriteString("      role_id_file_path   = \"/etc/vault-agent/role_id\"\n")
	b.WriteString("      secret_id_file_path = \"/etc/vault-agent/secret_id\"\n")
	b.WriteString("    }\n  }\n")
	b.WriteString("  sink \"file\" { config = { path = \"/etc/vault-agent/token\" } }\n")
	b.WriteString("}\n\n")
	fmt.Fprintf(&b, "# Issue the leaf from %s/issue/%s and render cert + key.\n", in.Mount, in.Role)
	b.WriteString("template {\n")
	fmt.Fprintf(&b, "  contents    = <<-EOT\n    {{- with secret \"%s/issue/%s\" \"common_name=%s\" -}}\n    {{ .Data.certificate }}\n    {{ range .Data.ca_chain }}{{ . }}\n    {{ end }}\n    {{- end -}}\n  EOT\n", in.Mount, in.Role, in.CommonName)
	fmt.Fprintf(&b, "  destination = \"/etc/tls/%s.crt\"\n", fileSafe(in.CommonName))
	b.WriteString(reloadLine(in.Service, "  "))
	b.WriteString("}\n\n")
	b.WriteString("template {\n")
	fmt.Fprintf(&b, "  contents    = <<-EOT\n    {{- with secret \"%s/issue/%s\" \"common_name=%s\" -}}\n    {{ .Data.private_key }}\n    {{- end -}}\n  EOT\n", in.Mount, in.Role, in.CommonName)
	fmt.Fprintf(&b, "  destination = \"/etc/tls/%s.key\"\n", fileSafe(in.CommonName))
	b.WriteString("}\n")
	return Artifact{Filename: "vault-agent.hcl", Language: "hcl", Content: b.String()}
}

func aapPlaybook(in KitInput) Artifact {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "# AAP playbook: reissue %s from Vault PKI and deploy.\n", in.CommonName)
	b.WriteString("- name: Reissue and deploy certificate\n")
	b.WriteString("  hosts: web\n")
	b.WriteString("  become: true\n")
	b.WriteString("  tasks:\n")
	b.WriteString("    - name: Issue leaf from Vault PKI\n")
	b.WriteString("      community.hashi_vault.vault_write:\n")
	fmt.Fprintf(&b, "        path: %s/issue/%s\n", in.Mount, in.Role)
	b.WriteString("        data:\n")
	fmt.Fprintf(&b, "          common_name: %s\n", in.CommonName)
	b.WriteString("      register: issued\n")
	b.WriteString("    - name: Write certificate\n")
	b.WriteString("      ansible.builtin.copy:\n")
	b.WriteString("        content: \"{{ issued.data.data.certificate }}\\n{{ issued.data.data.ca_chain | join('\\n') }}\"\n")
	fmt.Fprintf(&b, "        dest: /etc/tls/%s.crt\n", fileSafe(in.CommonName))
	b.WriteString("        mode: '0644'\n")
	b.WriteString("    - name: Write private key\n")
	b.WriteString("      ansible.builtin.copy:\n")
	b.WriteString("        content: \"{{ issued.data.data.private_key }}\"\n")
	fmt.Fprintf(&b, "        dest: /etc/tls/%s.key\n", fileSafe(in.CommonName))
	b.WriteString("        mode: '0600'\n")
	if strings.TrimSpace(in.Service) != "" {
		b.WriteString("    - name: Reload service\n")
		b.WriteString("      ansible.builtin.service:\n")
		fmt.Fprintf(&b, "        name: %s\n", in.Service)
		b.WriteString("        state: reloaded\n")
	}
	return Artifact{Filename: "reissue-playbook.yml", Language: "yaml", Content: b.String()}
}
