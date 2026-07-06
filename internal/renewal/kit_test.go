package renewal

import (
	"strings"
	"testing"
)

func TestGenerate_Agent(t *testing.T) {
	t.Parallel()

	arts, err := Generate(TargetAgent, KitInput{CommonName: "app.example.com", Mount: "pki", Role: "web", Service: "nginx"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(arts) != 1 || arts[0].Language != "hcl" {
		t.Fatalf("expected one hcl artifact, got %+v", arts)
	}
	c := arts[0].Content
	for _, want := range []string{"auto_auth", "pki/issue/web", "common_name=app.example.com", "/etc/tls/app.example.com.crt", "systemctl reload nginx"} {
		if !strings.Contains(c, want) {
			t.Fatalf("agent HCL missing %q\n%s", want, c)
		}
	}
}

func TestGenerate_AAP(t *testing.T) {
	t.Parallel()

	arts, err := Generate(TargetAAP, KitInput{CommonName: "api.example.com", Mount: "pki-int", Role: "svc", Service: "api"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(arts) != 1 || arts[0].Language != "yaml" {
		t.Fatalf("expected one yaml artifact, got %+v", arts)
	}
	c := arts[0].Content
	for _, want := range []string{"community.hashi_vault.vault_write", "path: pki-int/issue/svc", "common_name: api.example.com", "state: reloaded"} {
		if !strings.Contains(c, want) {
			t.Fatalf("aap playbook missing %q\n%s", want, c)
		}
	}
}

func TestGenerate_NoServiceOmitsReload(t *testing.T) {
	t.Parallel()

	agent, _ := Generate(TargetAgent, KitInput{CommonName: "x", Mount: "pki", Role: "r"})
	if strings.Contains(agent[0].Content, "systemctl reload") {
		t.Fatal("agent HCL should omit reload when no service")
	}
	aap, _ := Generate(TargetAAP, KitInput{CommonName: "x", Mount: "pki", Role: "r"})
	if strings.Contains(aap[0].Content, "state: reloaded") {
		t.Fatal("aap playbook should omit reload when no service")
	}
}

func TestGenerate_WildcardCN(t *testing.T) {
	t.Parallel()

	arts, err := Generate(TargetAgent, KitInput{CommonName: "*.example.com", Mount: "pki", Role: "web"})
	if err != nil {
		t.Fatalf("wildcard CN should be valid: %v", err)
	}
	c := arts[0].Content
	if !strings.Contains(c, "common_name=*.example.com") {
		t.Fatalf("issue arg should keep wildcard CN: %s", c)
	}
	if strings.Contains(c, "/etc/tls/*.example.com") {
		t.Fatal("file destination must not contain a literal '*'")
	}
	if !strings.Contains(c, "/etc/tls/wildcard.example.com.crt") {
		t.Fatalf("wildcard should be sanitized in the file path: %s", c)
	}
}

func TestGenerate_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target Target
		in     KitInput
	}{
		{"bad target", Target("nope"), KitInput{CommonName: "x", Mount: "pki", Role: "r"}},
		{"empty role", TargetAgent, KitInput{CommonName: "x", Mount: "pki", Role: ""}},
		{"traversal mount", TargetAgent, KitInput{CommonName: "x", Mount: "../sys", Role: "r"}},
		{"empty cn", TargetAgent, KitInput{CommonName: "", Mount: "pki", Role: "r"}},
		{"cn newline injection", TargetAgent, KitInput{CommonName: "a\ntemplate { command = \"sh\" }", Mount: "pki", Role: "r"}},
		{"cn quote breakout", TargetAgent, KitInput{CommonName: "a\" x=\"y", Mount: "pki", Role: "r"}},
		{"cn path traversal", TargetAgent, KitInput{CommonName: "../../root/.bashrc", Mount: "pki", Role: "r"}},
		{"cn template metachars", TargetAAP, KitInput{CommonName: "a}}b{{c", Mount: "pki", Role: "r"}},
		{"cn space", TargetAAP, KitInput{CommonName: "a b", Mount: "pki", Role: "r"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Generate(tt.target, tt.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
