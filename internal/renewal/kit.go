// Package renewal generates the reissue-and-deploy artifacts for the lifecycle
// "Mode C" step. CLM does not issue or deploy certificates itself (Vault PKI
// issues; vault-agent/AAP deploy); this package produces the operator-runnable
// artifacts, and CLM verifies the result via a later rescan + reconcile.
package renewal

import (
	"fmt"
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
	if strings.TrimSpace(in.CommonName) == "" {
		return fmt.Errorf("common name is required")
	}
	return nil
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
	fmt.Fprintf(&b, "  destination = \"/etc/tls/%s.crt\"\n", in.CommonName)
	b.WriteString(reloadLine(in.Service, "  "))
	b.WriteString("}\n\n")
	b.WriteString("template {\n")
	fmt.Fprintf(&b, "  contents    = <<-EOT\n    {{- with secret \"%s/issue/%s\" \"common_name=%s\" -}}\n    {{ .Data.private_key }}\n    {{- end -}}\n  EOT\n", in.Mount, in.Role, in.CommonName)
	fmt.Fprintf(&b, "  destination = \"/etc/tls/%s.key\"\n", in.CommonName)
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
	fmt.Fprintf(&b, "        dest: /etc/tls/%s.crt\n", in.CommonName)
	b.WriteString("        mode: '0644'\n")
	b.WriteString("    - name: Write private key\n")
	b.WriteString("      ansible.builtin.copy:\n")
	b.WriteString("        content: \"{{ issued.data.data.private_key }}\"\n")
	fmt.Fprintf(&b, "        dest: /etc/tls/%s.key\n", in.CommonName)
	b.WriteString("        mode: '0600'\n")
	if strings.TrimSpace(in.Service) != "" {
		b.WriteString("    - name: Reload service\n")
		b.WriteString("      ansible.builtin.service:\n")
		fmt.Fprintf(&b, "        name: %s\n", in.Service)
		b.WriteString("        state: reloaded\n")
	}
	return Artifact{Filename: "reissue-playbook.yml", Language: "yaml", Content: b.String()}
}
