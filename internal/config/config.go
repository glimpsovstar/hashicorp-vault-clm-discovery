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
	VaultAuthMethod         string        `envconfig:"VAULT_AUTH_METHOD" default:"token"` // token | approle | aws (only token impl required now)
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
}

func Load() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	return cfg, err
}
