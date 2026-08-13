package settings

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

func envCfg() config.Config {
	return config.Config{
		VaultAddr:        "https://env-vault.example:8200",
		VaultNamespace:   "env-ns",
		VaultToken:       "s.env-vault-token",
		VaultAuthMethod:  "token",
		AAPURL:           "https://env-aap.example",
		AAPToken:         "hvs.env-aap-token",
		AAPRenewTemplate: "CLM - Issue Certificate",
		AAPDefaultMount:  "pki",
		EDAWebhookURL:    "https://env-eda.example/hook",
		EDAWebhookToken:  "s.env-eda-token",
	}
}

func TestResolve_NoRowsUsesEnv(t *testing.T) {
	t.Parallel()

	got, err := Resolve(envCfg(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault.Address != "https://env-vault.example:8200" {
		t.Fatalf("Vault.Address = %q, want env", got.Vault.Address)
	}
	if got.Vault.Token != "s.env-vault-token" {
		t.Fatalf("Vault.Token = %q, want env token", got.Vault.Token)
	}
	if got.AAP.BaseURL != "https://env-aap.example" {
		t.Fatalf("AAP.BaseURL = %q, want env", got.AAP.BaseURL)
	}
	if got.EDA.WebhookURL != "https://env-eda.example/hook" {
		t.Fatalf("EDA.WebhookURL = %q, want env", got.EDA.WebhookURL)
	}
	if got.View.Vault.Source != "env" || got.View.AAP.Source != "env" || got.View.EDA.Source != "env" {
		t.Fatalf("sources = vault=%q aap=%q eda=%q, want env", got.View.Vault.Source, got.View.AAP.Source, got.View.EDA.Source)
	}
	if !got.View.Vault.Configured || !got.View.AAP.Configured || !got.View.EDA.Configured {
		t.Fatal("env addr/url should mark all three configured")
	}
	if !got.View.Vault.TokenSet || got.View.Vault.RoleIDSet || got.View.Vault.SecretIDSet {
		t.Fatalf("vault flags token_set=%v role_id_set=%v secret_id_set=%v", got.View.Vault.TokenSet, got.View.Vault.RoleIDSet, got.View.Vault.SecretIDSet)
	}
	if got.View.Vault.Deployment != "self_managed" {
		t.Fatalf("env-only deployment = %q, want self_managed", got.View.Vault.Deployment)
	}
	if got.View.Vault.AuthMethod != "token" {
		t.Fatalf("auth_method = %q, want token", got.View.Vault.AuthMethod)
	}
}

func TestResolve_DBSourceOverlaysEnv(t *testing.T) {
	t.Parallel()

	rows := []store.Connection{
		{
			Target:     "vault",
			Source:     "db",
			Metadata:   json.RawMessage(`{"deployment":"self_managed","addr":"https://db-vault.example:8200","namespace":"admin","auth_method":"approle"}`),
			SecretsSet: true,
		},
		{
			Target:     "aap",
			Source:     "db",
			Metadata:   json.RawMessage(`{"url":"https://db-aap.example","renew_template":"DB Template","renew_workflow":true,"skip_tls_verify":true,"default_mount":"pki-int"}`),
			SecretsSet: true,
		},
		{
			Target:     "eda",
			Source:     "db",
			Metadata:   json.RawMessage(`{"webhook_url":"https://db-eda.example/hook"}`),
			SecretsSet: true,
		},
	}
	secrets := map[string]map[string]string{
		"vault": {"role_id": "db-role", "secret_id": "db-secret"},
		"aap":   {"token": "db-aap-token"},
		"eda":   {"token": "db-eda-token"},
	}

	got, err := Resolve(envCfg(), rows, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault.Address != "https://db-vault.example:8200" {
		t.Fatalf("Vault.Address = %q, want db overlay", got.Vault.Address)
	}
	if got.Vault.Namespace != "admin" {
		t.Fatalf("Vault.Namespace = %q, want admin", got.Vault.Namespace)
	}
	if got.Vault.AuthMethod != "approle" {
		t.Fatalf("Vault.AuthMethod = %q, want approle", got.Vault.AuthMethod)
	}
	if got.Vault.RoleID != "db-role" || got.Vault.SecretID != "db-secret" {
		t.Fatalf("AppRole creds = %q/%q, want db overlay", got.Vault.RoleID, got.Vault.SecretID)
	}
	if got.Vault.Token != "s.env-vault-token" {
		t.Fatalf("unset db token should fall back to env, got %q", got.Vault.Token)
	}
	if got.AAP.BaseURL != "https://db-aap.example" || got.AAP.Token != "db-aap-token" || !got.AAP.SkipTLSVerify {
		t.Fatalf("AAP overlay = %+v", got.AAP)
	}
	if got.EDA.WebhookURL != "https://db-eda.example/hook" || got.EDA.Token != "db-eda-token" {
		t.Fatalf("EDA overlay = %+v", got.EDA)
	}
	if got.View.Vault.Source != "db" || got.View.AAP.Source != "db" || got.View.EDA.Source != "db" {
		t.Fatalf("view sources = vault=%q aap=%q eda=%q, want db", got.View.Vault.Source, got.View.AAP.Source, got.View.EDA.Source)
	}
	if !got.View.Vault.RoleIDSet || !got.View.Vault.SecretIDSet || !got.View.Vault.TokenSet {
		t.Fatalf("vault *_set flags = token=%v role=%v secret=%v", got.View.Vault.TokenSet, got.View.Vault.RoleIDSet, got.View.Vault.SecretIDSet)
	}
	if got.View.AAP.RenewTemplate != "DB Template" || !got.View.AAP.RenewWorkflow || got.View.AAP.DefaultMount != "pki-int" {
		t.Fatalf("AAP view metadata = %+v", got.View.AAP)
	}
}

func TestResolve_EmptyPatchTokenKeepsDBSecret(t *testing.T) {
	t.Parallel()

	cfg := envCfg()
	cfg.VaultToken = "s.env-should-not-win"
	rows := []store.Connection{{
		Target:     "vault",
		Source:     "db",
		Metadata:   json.RawMessage(`{"addr":"https://db-vault.example:8200","auth_method":"token"}`),
		SecretsSet: true,
	}}
	// keepSecrets / omitted PATCH token leaves the stored ciphertext; resolve sees it.
	secrets := map[string]map[string]string{
		"vault": {"token": "s.stored-after-omit-patch"},
	}

	got, err := Resolve(cfg, rows, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault.Token != "s.stored-after-omit-patch" {
		t.Fatalf("Vault.Token = %q, want stored secret after omit/keep PATCH", got.Vault.Token)
	}
	if !got.View.Vault.TokenSet {
		t.Fatal("token_set should be true when stored secret remains")
	}
}

func TestResolve_ClearedSecretFallsBackToEnv(t *testing.T) {
	t.Parallel()

	cfg := envCfg()
	rows := []store.Connection{{
		Target:   "vault",
		Source:   "db",
		Metadata: json.RawMessage(`{"addr":"https://db-vault.example:8200","auth_method":"token"}`),
	}}
	got, err := Resolve(cfg, rows, map[string]map[string]string{"vault": {}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault.Token != cfg.VaultToken {
		t.Fatalf("cleared db token should fall back to env, got %q", got.Vault.Token)
	}
	if got.Vault.Address != "https://db-vault.example:8200" {
		t.Fatalf("addr should still overlay, got %q", got.Vault.Address)
	}
}

func TestResolve_SourceEnvIgnoresDBMetadata(t *testing.T) {
	t.Parallel()

	rows := []store.Connection{{
		Target:   "vault",
		Source:   "env",
		Metadata: json.RawMessage(`{"addr":"https://db-vault.example:8200"}`),
	}}
	got, err := Resolve(envCfg(), rows, map[string]map[string]string{
		"vault": {"token": "s.db-ignored"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault.Address != "https://env-vault.example:8200" {
		t.Fatalf("source=env must use config addr, got %q", got.Vault.Address)
	}
	if got.Vault.Token != "s.env-vault-token" {
		t.Fatalf("source=env must use config token, got %q", got.Vault.Token)
	}
	if got.View.Vault.Source != "env" {
		t.Fatalf("source = %q, want env", got.View.Vault.Source)
	}
}

func TestResolve_HCPMetadataDoesNotChangeClientType(t *testing.T) {
	t.Parallel()

	hcpRows := []store.Connection{{
		Target:   "vault",
		Source:   "db",
		Metadata: json.RawMessage(`{"deployment":"hcp_dedicated","addr":"https://hcp.example:8200","namespace":"admin","auth_method":"token"}`),
	}}
	selfRows := []store.Connection{{
		Target:   "vault",
		Source:   "db",
		Metadata: json.RawMessage(`{"deployment":"self_managed","addr":"https://vault.example:8200","namespace":"","auth_method":"token"}`),
	}}

	hcp, err := Resolve(envCfg(), hcpRows, nil)
	if err != nil {
		t.Fatal(err)
	}
	self, err := Resolve(envCfg(), selfRows, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(hcp.Vault) != reflect.TypeOf(vault.Config{}) {
		t.Fatalf("HCP resolved type = %s, want vault.Config", reflect.TypeOf(hcp.Vault))
	}
	if reflect.TypeOf(hcp.Vault) != reflect.TypeOf(self.Vault) {
		t.Fatal("HCP vs self-managed must share one vault.Config client type")
	}
	if hcp.View.Vault.Deployment != "hcp_dedicated" {
		t.Fatalf("deployment = %q, want hcp_dedicated", hcp.View.Vault.Deployment)
	}
	if self.View.Vault.Deployment != "self_managed" {
		t.Fatalf("deployment = %q, want self_managed", self.View.Vault.Deployment)
	}
	hcpClient, err := vault.NewClient(hcp.Vault)
	if err != nil {
		t.Fatal(err)
	}
	selfClient, err := vault.NewClient(self.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if !hcpClient.Configured() || !selfClient.Configured() {
		t.Fatal("both deployments should produce a configured vault.Client")
	}
	if reflect.TypeOf(hcpClient) != reflect.TypeOf(selfClient) {
		t.Fatal("HCP metadata must not change vault.Client type")
	}
}
