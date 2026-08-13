package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Addr                    string        `envconfig:"ADDR" default:":8080"`
	DatabaseURL             string        `envconfig:"DATABASE_URL" required:"true"`
	ExpiringSoonDays        int           `envconfig:"EXPIRING_SOON_DAYS" default:"30"`
	ScanTimeout             time.Duration `envconfig:"SCAN_TIMEOUT" default:"5s"`
	DefaultConcurrency      int           `envconfig:"DEFAULT_CONCURRENCY" default:"50"`
	AllowPrivateRanges      bool          `envconfig:"ALLOW_PRIVATE_RANGES" default:"false"`
	CORSOrigins             []string      `envconfig:"CORS_ORIGINS" default:"http://localhost:3000"`
	LogLevel                string        `envconfig:"LOG_LEVEL" default:"info"`
	VaultAddr               string        `envconfig:"VAULT_ADDR" default:""`
	VaultNamespace          string        `envconfig:"VAULT_NAMESPACE" default:""`
	VaultToken              string        `envconfig:"VAULT_TOKEN" default:""`
	VaultAuthMethod         string        `envconfig:"VAULT_AUTH_METHOD" default:"token"` // token | approle
	VaultRoleID             string        `envconfig:"VAULT_ROLE_ID" default:""`          // AppRole; never logged
	VaultSecretID           string        `envconfig:"VAULT_SECRET_ID" default:""`
	ReconcileOnScanComplete bool          `envconfig:"RECONCILE_ON_SCAN_COMPLETE" default:"false"`
	// AAP (Ansible Automation Platform) drives Mode C renewals. When AAPURL is
	// empty the renew endpoint returns 503. Token/URL are read from the env and
	// never logged.
	AAPURL           string `envconfig:"AAP_URL" default:""`
	AAPToken         string `envconfig:"AAP_TOKEN" default:""`
	AAPRenewTemplate string `envconfig:"AAP_RENEW_TEMPLATE" default:"CLM - Issue Certificate"`
	AAPRenewWorkflow bool   `envconfig:"AAP_RENEW_WORKFLOW" default:"false"`
	AAPSkipTLSVerify bool   `envconfig:"AAP_SKIP_TLS_VERIFY" default:"false"`
	AAPDefaultMount  string `envconfig:"AAP_DEFAULT_MOUNT" default:"pki"`
	// Event dispatcher (ADR 0001, event Phase 1b). When EDAWebhookURL is empty the
	// dispatcher does not start. Token/URL are read from the env and never logged.
	EDAWebhookURL         string        `envconfig:"EDA_WEBHOOK_URL" default:""`
	EDAWebhookToken       string        `envconfig:"EDA_WEBHOOK_TOKEN" default:""`
	EventDispatchInterval time.Duration `envconfig:"EVENT_DISPATCH_INTERVAL" default:"15s"`
	EventDispatchBatch    int           `envconfig:"EVENT_DISPATCH_BATCH" default:"50"`
	EventMaxAttempts      int           `envconfig:"EVENT_MAX_ATTEMPTS" default:"10"`
	// ConnectionsKey is the AES-256-GCM key for Settings connection secrets
	// (32-byte raw or 64-char hex). Empty means env-only mode: Compose defaults
	// still work; persisting new secrets from the UI fails until the key is set.
	ConnectionsKey string `envconfig:"CLM_CONNECTIONS_KEY" default:""`
	// InsecureNoAuth is a UAT-only escape hatch (CLM_INSECURE_NO_AUTH). When
	// true, Settings handlers treat the caller as platform_admin. Default false:
	// unauthenticated Settings GET/PUT/PATCH return 401. Not a substitute for M1 RBAC.
	InsecureNoAuth bool `envconfig:"CLM_INSECURE_NO_AUTH" default:"false"`
}

func Load() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	return cfg, err
}
