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

func TestBuild_OptionalVarsAndConnection(t *testing.T) {
	t.Parallel()

	c := cert("app.example.com", "web-server", "nginx", 12)
	c.RenewalConfig.TargetHosts = "web_group"
	c.RenewalConfig.TTL = "72h"
	c.RenewalConfig.AltNames = "a.example.com,b.example.com"

	doc := Build([]store.Certificate{c})
	vars := doc["_meta"].(map[string]any)["hostvars"].(map[string]any)["app.example.com"].(map[string]any)

	if vars["ansible_connection"] != "local" {
		t.Fatalf("ansible_connection = %v, want local (metadata feed, not SSH targets)", vars["ansible_connection"])
	}
	if vars["clm_target_hosts"] != "web_group" {
		t.Fatalf("clm_target_hosts = %v", vars["clm_target_hosts"])
	}
	if vars["vault_cert_ttl"] != "72h" {
		t.Fatalf("vault_cert_ttl = %v", vars["vault_cert_ttl"])
	}
	if vars["cert_alt_names_override"] != "a.example.com,b.example.com" {
		t.Fatalf("cert_alt_names_override = %v", vars["cert_alt_names_override"])
	}
}

func TestBuild_SlugifiesServiceGroupNames(t *testing.T) {
	t.Parallel()

	// A service with '-'/'.' would produce an Ansible-warning group name.
	doc := Build([]store.Certificate{cert("x.example.com", "web", "web-server.v2", 5)})
	if _, ok := doc["svc_web_server_v2"].(map[string]any); !ok {
		t.Fatalf("expected slugified group svc_web_server_v2, got keys %v", keysOf(doc))
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func strptr(s string) *string { return &s }
