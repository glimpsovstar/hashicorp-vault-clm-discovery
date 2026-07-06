package inventory

import (
	"testing"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func cert(cn, role, service string, days int) store.Certificate {
	c := cn
	return store.Certificate{
		ID:              uuid.New(),
		SubjectCN:       &c,
		DaysUntilExpiry: days,
		RenewalConfig:   &store.RenewalConfig{Role: role, Mount: "pki-int", Service: service},
	}
}

func TestBuild_HostsVarsAndGroups(t *testing.T) {
	t.Parallel()

	certs := []store.Certificate{
		cert("a.example.com", "web-server", "nginx", 10),
		cert("b.example.com", "web-server", "nginx", 20),
		cert("c.example.com", "api-server", "tomcat", 5),
	}
	doc := Build(certs)

	meta, ok := doc["_meta"].(map[string]any)
	if !ok {
		t.Fatal("_meta missing")
	}
	hostvars, ok := meta["hostvars"].(map[string]any)
	if !ok || len(hostvars) != 3 {
		t.Fatalf("hostvars = %#v, want 3 entries", meta["hostvars"])
	}

	av, ok := hostvars["a.example.com"].(map[string]any)
	if !ok {
		t.Fatal("a.example.com hostvars missing")
	}
	if av["cert_common_name_override"] != "a.example.com" || av["vault_pki_role"] != "web-server" ||
		av["vault_pki_mount"] != "pki-int" || av["cert_service_type"] != "nginx" {
		t.Fatalf("unexpected hostvars for a: %#v", av)
	}
	if av["clm_days_until_expiry"] != 10 {
		t.Fatalf("clm_days_until_expiry = %v, want 10", av["clm_days_until_expiry"])
	}

	renewable, ok := doc["clm_renewable"].(map[string]any)
	if !ok {
		t.Fatal("clm_renewable group missing")
	}
	if hosts, _ := renewable["hosts"].([]string); len(hosts) != 3 {
		t.Fatalf("clm_renewable hosts = %#v, want 3", renewable["hosts"])
	}

	// Service groups.
	nginx, ok := doc["svc_nginx"].(map[string]any)
	if !ok {
		t.Fatal("svc_nginx group missing")
	}
	if hosts, _ := nginx["hosts"].([]string); len(hosts) != 2 {
		t.Fatalf("svc_nginx hosts = %#v, want 2", nginx["hosts"])
	}
	if _, ok := doc["svc_tomcat"].(map[string]any); !ok {
		t.Fatal("svc_tomcat group missing")
	}

	all, ok := doc["all"].(map[string]any)
	if !ok {
		t.Fatal("all group missing")
	}
	children, _ := all["children"].([]string)
	if len(children) != 3 { // clm_renewable + svc_nginx + svc_tomcat
		t.Fatalf("all.children = %#v, want 3", children)
	}
}

func TestBuild_SkipsNilConfigAndEmptyCN(t *testing.T) {
	t.Parallel()

	empty := ""
	certs := []store.Certificate{
		cert("good.example.com", "web", "nginx", 10),
		{ID: uuid.New(), SubjectCN: &empty, RenewalConfig: &store.RenewalConfig{Role: "web", Mount: "pki"}}, // empty CN
		{ID: uuid.New(), SubjectCN: strptr("no-config.example.com")},                                        // nil RenewalConfig
	}
	doc := Build(certs)
	hostvars := doc["_meta"].(map[string]any)["hostvars"].(map[string]any)
	if len(hostvars) != 1 {
		t.Fatalf("hostvars = %#v, want only the valid cert", hostvars)
	}
	if _, ok := hostvars["good.example.com"]; !ok {
		t.Fatal("expected good.example.com to be included")
	}
}

func TestBuild_DedupesByCN(t *testing.T) {
	t.Parallel()

	certs := []store.Certificate{
		cert("dup.example.com", "first", "nginx", 10),
		cert("dup.example.com", "second", "tomcat", 5),
	}
	doc := Build(certs)
	hostvars := doc["_meta"].(map[string]any)["hostvars"].(map[string]any)
	if len(hostvars) != 1 {
		t.Fatalf("hostvars = %#v, want 1 (deduped)", hostvars)
	}
	if hostvars["dup.example.com"].(map[string]any)["vault_pki_role"] != "first" {
		t.Fatal("expected the first occurrence to win")
	}
}

func TestBuild_EmptyIsValid(t *testing.T) {
	t.Parallel()

	doc := Build(nil)
	renewable := doc["clm_renewable"].(map[string]any)
	hosts, ok := renewable["hosts"].([]string)
	if !ok || len(hosts) != 0 {
		t.Fatalf("empty inventory should have an empty hosts slice, got %#v", renewable["hosts"])
	}
	if _, ok := doc["_meta"].(map[string]any)["hostvars"].(map[string]any); !ok {
		t.Fatal("_meta.hostvars should be present even when empty")
	}
}

func strptr(s string) *string { return &s }
