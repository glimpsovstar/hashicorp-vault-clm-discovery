// Package settings resolves Vault, AAP, and EDA connection config.
//
// Env (VAULT_*, AAP_*, EDA_*) is the 12-factor default. A connections row with
// source=db overlays that deployment for that target. Secrets never appear in
// PublicView; only *_set flags.
package settings

import (
	"encoding/json"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/aap"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/eventbus"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/vault"
)

// Resolved is the runtime connection set plus the masked operator view.
// Vault, AAP, and EDA use the existing client config types; HCP vs
// self-managed is metadata only and does not change client type.
type Resolved struct {
	Vault vault.Config
	AAP   aap.Config
	EDA   eventbus.Config
	View  PublicView
}

// PublicView is the GET /settings/connections JSON body. It never includes
// token, role_id, or secret_id values.
type PublicView struct {
	Vault VaultPublic `json:"vault"`
	AAP   AAPPublic   `json:"aap"`
	EDA   EDAPublic   `json:"eda"`
}

// VaultPublic is the masked Vault card.
type VaultPublic struct {
	Configured  bool   `json:"configured"`
	Source      string `json:"source"`
	Deployment  string `json:"deployment"`
	Addr        string `json:"addr"`
	Namespace   string `json:"namespace"`
	AuthMethod  string `json:"auth_method"`
	TokenSet    bool   `json:"token_set"`
	RoleIDSet   bool   `json:"role_id_set"`
	SecretIDSet bool   `json:"secret_id_set"`
}

// AAPPublic is the masked AAP Controller card.
type AAPPublic struct {
	Configured    bool   `json:"configured"`
	Source        string `json:"source"`
	URL           string `json:"url"`
	RenewTemplate string `json:"renew_template"`
	RenewWorkflow bool   `json:"renew_workflow"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	DefaultMount  string `json:"default_mount"`
	TokenSet      bool   `json:"token_set"`
}

// EDAPublic is the masked EDA webhook card.
type EDAPublic struct {
	Configured bool   `json:"configured"`
	Source     string `json:"source"`
	WebhookURL string `json:"webhook_url"`
	TokenSet   bool   `json:"token_set"`
}

type vaultMeta struct {
	Deployment string  `json:"deployment"`
	Addr       string  `json:"addr"`
	Namespace  *string `json:"namespace"`
	AuthMethod string  `json:"auth_method"`
}

type aapMeta struct {
	URL           string `json:"url"`
	RenewTemplate string `json:"renew_template"`
	RenewWorkflow *bool  `json:"renew_workflow"`
	SkipTLSVerify *bool  `json:"skip_tls_verify"`
	DefaultMount  string `json:"default_mount"`
}

type edaMeta struct {
	WebhookURL string `json:"webhook_url"`
}

// Resolve overlays DB connection rows onto env config. No row or source=env
// uses config env for that target. source=db overlays metadata and any
// decrypted secrets; missing secret keys fall back to env (cleared JSON null).
func Resolve(cfg config.Config, rows []store.Connection, secretsByTarget map[string]map[string]string) (Resolved, error) {
	byTarget := map[string]store.Connection{}
	for _, row := range rows {
		byTarget[row.Target] = row
	}
	if secretsByTarget == nil {
		secretsByTarget = map[string]map[string]string{}
	}

	vc, vview, err := resolveVault(cfg, byTarget["vault"], secretsByTarget["vault"])
	if err != nil {
		return Resolved{}, err
	}
	ac, aview, err := resolveAAP(cfg, byTarget["aap"], secretsByTarget["aap"])
	if err != nil {
		return Resolved{}, err
	}
	ec, eview, err := resolveEDA(cfg, byTarget["eda"], secretsByTarget["eda"])
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{
		Vault: vc,
		AAP:   ac,
		EDA:   ec,
		View:  PublicView{Vault: vview, AAP: aview, EDA: eview},
	}, nil
}

func resolveVault(cfg config.Config, row store.Connection, secrets map[string]string) (vault.Config, VaultPublic, error) {
	out := vault.Config{
		Address:    cfg.VaultAddr,
		Namespace:  cfg.VaultNamespace,
		Token:      cfg.VaultToken,
		AuthMethod: cfg.VaultAuthMethod,
		RoleID:     cfg.VaultRoleID,
		SecretID:   cfg.VaultSecretID,
	}
	if out.AuthMethod == "" {
		out.AuthMethod = "token"
	}
	source := "env"
	deployment := "self_managed"
	if row.Target == "vault" && row.Source == "db" {
		source = "db"
		var meta vaultMeta
		if len(row.Metadata) > 0 {
			if err := json.Unmarshal(row.Metadata, &meta); err != nil {
				return vault.Config{}, VaultPublic{}, err
			}
		}
		if meta.Addr != "" {
			out.Address = meta.Addr
		}
		if meta.Namespace != nil {
			out.Namespace = *meta.Namespace
		}
		if meta.AuthMethod != "" {
			out.AuthMethod = meta.AuthMethod
		}
		if meta.Deployment != "" {
			deployment = meta.Deployment
		}
		if v := secrets["token"]; v != "" {
			out.Token = v
		}
		if v := secrets["role_id"]; v != "" {
			out.RoleID = v
		}
		if v := secrets["secret_id"]; v != "" {
			out.SecretID = v
		}
	}
	return out, VaultPublic{
		Configured:  out.Address != "",
		Source:      source,
		Deployment:  deployment,
		Addr:        out.Address,
		Namespace:   out.Namespace,
		AuthMethod:  out.AuthMethod,
		TokenSet:    out.Token != "",
		RoleIDSet:   out.RoleID != "",
		SecretIDSet: out.SecretID != "",
	}, nil
}

func resolveAAP(cfg config.Config, row store.Connection, secrets map[string]string) (aap.Config, AAPPublic, error) {
	out := aap.Config{
		BaseURL:       cfg.AAPURL,
		Token:         cfg.AAPToken,
		SkipTLSVerify: cfg.AAPSkipTLSVerify,
	}
	template := cfg.AAPRenewTemplate
	workflow := cfg.AAPRenewWorkflow
	mount := cfg.AAPDefaultMount
	source := "env"
	if row.Target == "aap" && row.Source == "db" {
		source = "db"
		var meta aapMeta
		if len(row.Metadata) > 0 {
			if err := json.Unmarshal(row.Metadata, &meta); err != nil {
				return aap.Config{}, AAPPublic{}, err
			}
		}
		if meta.URL != "" {
			out.BaseURL = meta.URL
		}
		if meta.RenewTemplate != "" {
			template = meta.RenewTemplate
		}
		if meta.RenewWorkflow != nil {
			workflow = *meta.RenewWorkflow
		}
		if meta.SkipTLSVerify != nil {
			out.SkipTLSVerify = *meta.SkipTLSVerify
		}
		if meta.DefaultMount != "" {
			mount = meta.DefaultMount
		}
		if v := secrets["token"]; v != "" {
			out.Token = v
		}
	}
	return out, AAPPublic{
		Configured:    out.BaseURL != "",
		Source:        source,
		URL:           out.BaseURL,
		RenewTemplate: template,
		RenewWorkflow: workflow,
		SkipTLSVerify: out.SkipTLSVerify,
		DefaultMount:  mount,
		TokenSet:      out.Token != "",
	}, nil
}

func resolveEDA(cfg config.Config, row store.Connection, secrets map[string]string) (eventbus.Config, EDAPublic, error) {
	out := eventbus.Config{
		WebhookURL:  cfg.EDAWebhookURL,
		Token:       cfg.EDAWebhookToken,
		Interval:    cfg.EventDispatchInterval,
		BatchSize:   cfg.EventDispatchBatch,
		MaxAttempts: cfg.EventMaxAttempts,
	}
	source := "env"
	if row.Target == "eda" && row.Source == "db" {
		source = "db"
		var meta edaMeta
		if len(row.Metadata) > 0 {
			if err := json.Unmarshal(row.Metadata, &meta); err != nil {
				return eventbus.Config{}, EDAPublic{}, err
			}
		}
		if meta.WebhookURL != "" {
			out.WebhookURL = meta.WebhookURL
		}
		if v := secrets["token"]; v != "" {
			out.Token = v
		}
	}
	return out, EDAPublic{
		Configured: out.WebhookURL != "",
		Source:     source,
		WebhookURL: out.WebhookURL,
		TokenSet:   out.Token != "",
	}, nil
}
