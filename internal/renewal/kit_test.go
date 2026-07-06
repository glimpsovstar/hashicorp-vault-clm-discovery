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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Generate(tt.target, tt.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
