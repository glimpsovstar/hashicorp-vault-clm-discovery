package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Roles allowed in CLM_STATIC_TOKENS (M1 static_token AuthN).
var knownStaticRoles = map[string]struct{}{
	"viewer":             {},
	"scanner_operator":   {},
	"remediator":         {},
	"vault_import_admin": {},
	"approver":           {},
	"platform_admin":     {},
	"inventory":          {},
}

type Config struct {
	Addr               string        `envconfig:"ADDR" default:":8080"`
	DatabaseURL        string        `envconfig:"DATABASE_URL" required:"true"`
	ExpiringSoonDays   int           `envconfig:"EXPIRING_SOON_DAYS" default:"30"`
	ScanTimeout        time.Duration `envconfig:"SCAN_TIMEOUT" default:"5s"`
	DefaultConcurrency int           `envconfig:"DEFAULT_CONCURRENCY" default:"50"`
	AllowPrivateRanges bool          `envconfig:"ALLOW_PRIVATE_RANGES" default:"false"`
	CORSOrigins        []string      `envconfig:"CORS_ORIGINS" default:"http://localhost:3000"`
	LogLevel           string        `envconfig:"LOG_LEVEL" default:"info"`
	// Scan queue (M4): Postgres is the queue; these tune the claim poller.
	ScanQueueMaxPending int           `envconfig:"SCAN_QUEUE_MAX_PENDING" default:"32"`
	ScanWorkerSlots     int           `envconfig:"SCAN_WORKER_SLOTS" default:"2"`
	ScanClaimInterval   time.Duration `envconfig:"SCAN_CLAIM_INTERVAL" default:"2s"`
	ScanLeaseTTL        time.Duration `envconfig:"SCAN_LEASE_TTL" default:"30s"`
	ScanWorkerID        string        `envconfig:"SCAN_WORKER_ID" default:""`
	VaultAddr           string        `envconfig:"VAULT_ADDR" default:""`
	VaultNamespace      string        `envconfig:"VAULT_NAMESPACE" default:""`
	VaultToken          string        `envconfig:"VAULT_TOKEN" default:""`
	VaultAuthMethod     string        `envconfig:"VAULT_AUTH_METHOD" default:"token"` // token | approle
	VaultRoleID         string        `envconfig:"VAULT_ROLE_ID" default:""`          // AppRole; never logged
	VaultSecretID       string        `envconfig:"VAULT_SECRET_ID" default:""`
	// Import identity is separate from the read/reconcile client. Never logged.
	// Empty VaultImportAuthMethod inherits the read method, or token if only
	// VAULT_IMPORT_TOKEN is set (approle if only import role+secret are set).
	VaultImportToken        string `envconfig:"VAULT_IMPORT_TOKEN" default:""`
	VaultImportAuthMethod   string `envconfig:"VAULT_IMPORT_AUTH_METHOD" default:""`
	VaultImportRoleID       string `envconfig:"VAULT_IMPORT_ROLE_ID" default:""`
	VaultImportSecretID     string `envconfig:"VAULT_IMPORT_SECRET_ID" default:""`
	ReconcileOnScanComplete bool   `envconfig:"RECONCILE_ON_SCAN_COMPLETE" default:"false"`
	// AAP (Ansible Automation Platform) drives Mode C renewals. When AAPURL is
	// empty the renew endpoint returns 503. Token/URL are read from the env and
	// never logged.
	AAPURL            string `envconfig:"AAP_URL" default:""`
	AAPToken          string `envconfig:"AAP_TOKEN" default:""`
	AAPRenewTemplate  string `envconfig:"AAP_RENEW_TEMPLATE" default:"CLM - Issue Certificate"`
	AAPRenewWorkflow  bool   `envconfig:"AAP_RENEW_WORKFLOW" default:"false"`
	AAPRevokeTemplate string `envconfig:"AAP_REVOKE_TEMPLATE" default:"CLM - Revoke Certificate"`
	AAPRevokeWorkflow bool   `envconfig:"AAP_REVOKE_WORKFLOW" default:"false"`
	AAPSkipTLSVerify  bool   `envconfig:"AAP_SKIP_TLS_VERIFY" default:"false"`
	AAPDefaultMount   string `envconfig:"AAP_DEFAULT_MOUNT" default:"pki"`
	// Event dispatcher (ADR 0001, event Phase 1b). When EDAWebhookURL is empty the
	// dispatcher does not start. Token/URL are read from the env and never logged.
	EDAWebhookURL   string `envconfig:"EDA_WEBHOOK_URL" default:""`
	EDAWebhookToken string `envconfig:"EDA_WEBHOOK_TOKEN" default:""`
	// ITSM webhook (M5): optional HTTP sink for catalogue events. Empty ⇒ disabled.
	// HMAC secret is never logged; when set, requests include X-CLM-Signature.
	ITSMWebhookURL        string        `envconfig:"ITSM_WEBHOOK_URL" default:""`
	ITSMWebhookHMACSecret string        `envconfig:"ITSM_WEBHOOK_HMAC_SECRET" default:""`
	EventDispatchInterval time.Duration `envconfig:"EVENT_DISPATCH_INTERVAL" default:"15s"`
	EventDispatchBatch    int           `envconfig:"EVENT_DISPATCH_BATCH" default:"50"`
	EventMaxAttempts      int           `envconfig:"EVENT_MAX_ATTEMPTS" default:"10"`
	// Lifecycle verify (Mode C migrate / renew): Pending until wire predicate or timeout.
	LifecycleVerifyTimeout time.Duration `envconfig:"LIFECYCLE_VERIFY_TIMEOUT" default:"24h"`
	LifecycleVerifyPoll    time.Duration `envconfig:"LIFECYCLE_VERIFY_POLL_INTERVAL" default:"5s"`
	// ConnectionsKey is the AES-256-GCM key for Settings connection secrets
	// (32-byte raw or 64-char hex). Empty means env-only mode: Compose defaults
	// still work; persisting new secrets from the UI fails until the key is set.
	ConnectionsKey string `envconfig:"CLM_CONNECTIONS_KEY" default:""`
	// InsecureNoAuth is a UAT-only escape hatch (CLM_INSECURE_NO_AUTH). When
	// true, auth middleware skips Bearer checks and handlers treat the caller as
	// platform_admin. Default false: unauthenticated /api/v1 requests return 401
	// except GET /api/v1/health. Not a production auth substitute.
	InsecureNoAuth bool `envconfig:"CLM_INSECURE_NO_AUTH" default:"false"`
	// AuthMode selects control-plane AuthN (CLM_AUTH_MODE). Default static_token;
	// empty is treated as static_token. Unknown values are rejected at Load.
	AuthMode string `envconfig:"CLM_AUTH_MODE" default:"static_token"`
	// StaticTokensRaw is the raw CLM_STATIC_TOKENS spec (comma-separated
	// role:token). Hashed tokens use sha256:<hex> and contain a colon, so this
	// is parsed into StaticTokens instead of envconfig's map syntax.
	StaticTokensRaw string `envconfig:"CLM_STATIC_TOKENS" default:""`
	// StaticTokens maps role → plaintext token or sha256:<hex>. Filled by Load
	// from StaticTokensRaw; tests may set it directly.
	StaticTokens map[string]string `envconfig:"-"`
}

func Load() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.normalizeAuth(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) normalizeAuth() error {
	mode := strings.TrimSpace(c.AuthMode)
	if mode == "" {
		mode = "static_token"
	}
	if mode != "static_token" {
		return fmt.Errorf("CLM_AUTH_MODE: unknown mode %q (want static_token)", mode)
	}
	c.AuthMode = mode

	tokens, err := parseStaticTokens(c.StaticTokensRaw)
	if err != nil {
		return err
	}
	c.StaticTokens = tokens
	return nil
}

// AuthPostureWarnings returns operator-facing warnings for insecure or
// unusable AuthN config. Callers should log them at Warn and continue;
// startup must not fail.
func AuthPostureWarnings(cfg Config) []string {
	var out []string
	if cfg.InsecureNoAuth {
		out = append(out, "CLM_INSECURE_NO_AUTH=true: hatch grants platform_admin on all /api/v1")
	}
	mode := strings.TrimSpace(cfg.AuthMode)
	if mode == "" {
		mode = "static_token"
	}
	if mode == "static_token" && len(cfg.StaticTokens) == 0 && !cfg.InsecureNoAuth {
		out = append(out, "CLM_AUTH_MODE=static_token with empty CLM_STATIC_TOKENS: API will 401 everything except health")
	}
	return out
}

func parseStaticTokens(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]string{}, nil
	}
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		role, token, ok := strings.Cut(part, ":")
		role = strings.TrimSpace(role)
		token = strings.TrimSpace(token)
		if !ok || role == "" || token == "" {
			return nil, fmt.Errorf("CLM_STATIC_TOKENS: invalid entry %q (want role:token)", part)
		}
		if _, known := knownStaticRoles[role]; !known {
			return nil, fmt.Errorf("CLM_STATIC_TOKENS: unknown role %q", role)
		}
		if _, dup := out[role]; dup {
			return nil, fmt.Errorf("CLM_STATIC_TOKENS: duplicate role %q", role)
		}
		if err := validateStaticTokenSecret(role, token); err != nil {
			return nil, err
		}
		out[role] = token
	}
	return out, nil
}

func validateStaticTokenSecret(role, token string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(token, prefix) {
		return nil
	}
	digest := strings.TrimPrefix(token, prefix)
	if len(digest) != hex.EncodedLen(sha256.Size) {
		return fmt.Errorf("CLM_STATIC_TOKENS: role %q sha256 digest must be 64 hex chars", role)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("CLM_STATIC_TOKENS: role %q sha256 digest is not hex: %w", role, err)
	}
	return nil
}

// LookupStaticRole returns the role bound to a presented Bearer token.
func (c Config) LookupStaticRole(presented string) (string, bool) {
	if presented == "" || len(c.StaticTokens) == 0 {
		return "", false
	}
	for role, configured := range c.StaticTokens {
		if staticTokenMatches(configured, presented) {
			return role, true
		}
	}
	return "", false
}

func staticTokenMatches(configured, presented string) bool {
	const prefix = "sha256:"
	if strings.HasPrefix(configured, prefix) {
		want, err := hex.DecodeString(strings.TrimPrefix(configured, prefix))
		if err != nil || len(want) != sha256.Size {
			return false
		}
		got := sha256.Sum256([]byte(presented))
		return subtle.ConstantTimeCompare(want, got[:]) == 1
	}
	if len(configured) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configured), []byte(presented)) == 1
}

// HasVaultImportIdentity reports whether a dedicated Vault write identity is
// configured (import token and/or import AppRole). The read/reconcile identity
// does not count.
func (c Config) HasVaultImportIdentity() bool {
	if strings.TrimSpace(c.VaultImportToken) != "" {
		return true
	}
	return strings.TrimSpace(c.VaultImportRoleID) != "" && strings.TrimSpace(c.VaultImportSecretID) != ""
}

// ResolveVaultImportAuthMethod returns the auth method for the import client.
// VAULT_IMPORT_AUTH_METHOD wins when set. Otherwise: token if only an import
// token is present, approle if only import role+secret are present, else the
// read client's method (default token).
func (c Config) ResolveVaultImportAuthMethod() string {
	if m := strings.TrimSpace(c.VaultImportAuthMethod); m != "" {
		return m
	}
	hasToken := strings.TrimSpace(c.VaultImportToken) != ""
	hasAppRole := strings.TrimSpace(c.VaultImportRoleID) != "" && strings.TrimSpace(c.VaultImportSecretID) != ""
	switch {
	case hasToken && !hasAppRole:
		return "token"
	case hasAppRole && !hasToken:
		return "approle"
	}
	if m := strings.TrimSpace(c.VaultAuthMethod); m != "" {
		return m
	}
	return "token"
}
