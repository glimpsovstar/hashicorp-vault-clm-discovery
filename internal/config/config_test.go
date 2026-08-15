package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

var configEnvKeys = []string{
	"ADDR",
	"DATABASE_URL",
	"EXPIRING_SOON_DAYS",
	"SCAN_TIMEOUT",
	"DEFAULT_CONCURRENCY",
	"ALLOW_PRIVATE_RANGES",
	"CORS_ORIGINS",
	"LOG_LEVEL",
	"SCAN_QUEUE_MAX_PENDING",
	"SCAN_WORKER_SLOTS",
	"SCAN_CLAIM_INTERVAL",
	"SCAN_LEASE_TTL",
	"SCAN_WORKER_ID",
	"LIFECYCLE_VERIFY_TIMEOUT",
	"LIFECYCLE_VERIFY_POLL_INTERVAL",
	"CLM_CONNECTIONS_KEY",
	"CLM_INSECURE_NO_AUTH",
	"CLM_AUTH_MODE",
	"CLM_STATIC_TOKENS",
	"VAULT_ROLE_ID",
	"VAULT_SECRET_ID",
	"VAULT_AUTH_METHOD",
	"VAULT_IMPORT_TOKEN",
	"VAULT_IMPORT_ROLE_ID",
	"VAULT_IMPORT_SECRET_ID",
	"VAULT_IMPORT_AUTH_METHOD",
}

func resetConfigEnv(t *testing.T) {
	t.Helper()
	saved := make(map[string]string)
	for _, key := range configEnvKeys {
		if v, ok := os.LookupEnv(key); ok {
			saved[key] = v
		}
		os.Unsetenv(key)
	}
	t.Cleanup(func() {
		for _, key := range configEnvKeys {
			os.Unsetenv(key)
			if v, ok := saved[key]; ok {
				os.Setenv(key, v)
			}
		}
	})
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	resetConfigEnv(t)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when DATABASE_URL is unset")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Fatalf("expected DATABASE_URL in error, got %v", err)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":8080" {
		t.Fatalf("Addr = %q, want :8080", cfg.Addr)
	}
	if cfg.ExpiringSoonDays != 30 {
		t.Fatalf("ExpiringSoonDays = %d, want 30", cfg.ExpiringSoonDays)
	}
	if cfg.ScanTimeout != 5*time.Second {
		t.Fatalf("ScanTimeout = %v, want 5s", cfg.ScanTimeout)
	}
	if cfg.DefaultConcurrency != 50 {
		t.Fatalf("DefaultConcurrency = %d, want 50", cfg.DefaultConcurrency)
	}
	if cfg.AllowPrivateRanges {
		t.Fatal("AllowPrivateRanges should default to false")
	}
	if len(cfg.CORSOrigins) != 1 || cfg.CORSOrigins[0] != "http://localhost:3000" {
		t.Fatalf("CORSOrigins = %#v", cfg.CORSOrigins)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.LifecycleVerifyTimeout != 24*time.Hour {
		t.Fatalf("LifecycleVerifyTimeout = %v, want 24h", cfg.LifecycleVerifyTimeout)
	}
	if cfg.LifecycleVerifyPoll != 5*time.Second {
		t.Fatalf("LifecycleVerifyPoll = %v, want 5s", cfg.LifecycleVerifyPoll)
	}
	if cfg.ConnectionsKey != "" {
		t.Fatalf("ConnectionsKey = %q, want empty", cfg.ConnectionsKey)
	}
	if cfg.VaultRoleID != "" {
		t.Fatalf("VaultRoleID = %q, want empty", cfg.VaultRoleID)
	}
	if cfg.VaultSecretID != "" {
		t.Fatalf("VaultSecretID = %q, want empty", cfg.VaultSecretID)
	}
	if cfg.VaultAuthMethod != "token" {
		t.Fatalf("VaultAuthMethod = %q, want token", cfg.VaultAuthMethod)
	}
	if cfg.VaultImportToken != "" {
		t.Fatalf("VaultImportToken = %q, want empty", cfg.VaultImportToken)
	}
	if cfg.VaultImportRoleID != "" {
		t.Fatalf("VaultImportRoleID = %q, want empty", cfg.VaultImportRoleID)
	}
	if cfg.VaultImportSecretID != "" {
		t.Fatalf("VaultImportSecretID = %q, want empty", cfg.VaultImportSecretID)
	}
	if cfg.VaultImportAuthMethod != "" {
		t.Fatalf("VaultImportAuthMethod = %q, want empty", cfg.VaultImportAuthMethod)
	}
	if cfg.InsecureNoAuth {
		t.Fatal("InsecureNoAuth should default to false")
	}
	if cfg.AuthMode != "static_token" {
		t.Fatalf("AuthMode = %q, want static_token", cfg.AuthMode)
	}
	if len(cfg.StaticTokens) != 0 {
		t.Fatalf("StaticTokens = %#v, want empty", cfg.StaticTokens)
	}
}

func TestLoadReadsCustomValues(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://db/clm")
	t.Setenv("ADDR", ":9090")
	t.Setenv("EXPIRING_SOON_DAYS", "14")
	t.Setenv("SCAN_TIMEOUT", "10s")
	t.Setenv("DEFAULT_CONCURRENCY", "10")
	t.Setenv("ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("CORS_ORIGINS", "http://a.example,http://b.example")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("CLM_CONNECTIONS_KEY", strings.Repeat("ab", 32))
	t.Setenv("CLM_INSECURE_NO_AUTH", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9090" {
		t.Fatalf("Addr = %q", cfg.Addr)
	}
	if cfg.ExpiringSoonDays != 14 {
		t.Fatalf("ExpiringSoonDays = %d", cfg.ExpiringSoonDays)
	}
	if cfg.ScanTimeout != 10*time.Second {
		t.Fatalf("ScanTimeout = %v", cfg.ScanTimeout)
	}
	if cfg.DefaultConcurrency != 10 {
		t.Fatalf("DefaultConcurrency = %d", cfg.DefaultConcurrency)
	}
	if !cfg.AllowPrivateRanges {
		t.Fatal("expected AllowPrivateRanges true")
	}
	if len(cfg.CORSOrigins) != 2 {
		t.Fatalf("CORSOrigins = %#v", cfg.CORSOrigins)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.ConnectionsKey != strings.Repeat("ab", 32) {
		t.Fatalf("ConnectionsKey = %q", cfg.ConnectionsKey)
	}
	if !cfg.InsecureNoAuth {
		t.Fatal("expected InsecureNoAuth true")
	}
}

func TestLoadReadsVaultAppRole(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("VAULT_AUTH_METHOD", "approle")
	t.Setenv("VAULT_ROLE_ID", "role-uuid")
	t.Setenv("VAULT_SECRET_ID", "secret-uuid")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VaultAuthMethod != "approle" {
		t.Fatalf("VaultAuthMethod = %q, want approle", cfg.VaultAuthMethod)
	}
	if cfg.VaultRoleID != "role-uuid" {
		t.Fatalf("VaultRoleID = %q, want role-uuid", cfg.VaultRoleID)
	}
	if cfg.VaultSecretID != "secret-uuid" {
		t.Fatalf("VaultSecretID = %q, want secret-uuid", cfg.VaultSecretID)
	}
}

func TestLoadReadsVaultImportIdentity(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("VAULT_IMPORT_TOKEN", "hvs.import")
	t.Setenv("VAULT_IMPORT_AUTH_METHOD", "approle")
	t.Setenv("VAULT_IMPORT_ROLE_ID", "import-role")
	t.Setenv("VAULT_IMPORT_SECRET_ID", "import-secret")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VaultImportToken != "hvs.import" {
		t.Fatalf("VaultImportToken = %q, want hvs.import", cfg.VaultImportToken)
	}
	if cfg.VaultImportAuthMethod != "approle" {
		t.Fatalf("VaultImportAuthMethod = %q, want approle", cfg.VaultImportAuthMethod)
	}
	if cfg.VaultImportRoleID != "import-role" {
		t.Fatalf("VaultImportRoleID = %q, want import-role", cfg.VaultImportRoleID)
	}
	if cfg.VaultImportSecretID != "import-secret" {
		t.Fatalf("VaultImportSecretID = %q, want import-secret", cfg.VaultImportSecretID)
	}
}

func TestHasVaultImportIdentity(t *testing.T) {
	t.Parallel()

	if (Config{VaultToken: "read"}).HasVaultImportIdentity() {
		t.Fatal("read-only token must not count as import identity")
	}
	if (Config{VaultRoleID: "r", VaultSecretID: "s"}).HasVaultImportIdentity() {
		t.Fatal("read AppRole must not count as import identity")
	}
	if !(Config{VaultImportToken: "hvs.import"}).HasVaultImportIdentity() {
		t.Fatal("VAULT_IMPORT_TOKEN must count as import identity")
	}
	if !(Config{VaultImportRoleID: "r", VaultImportSecretID: "s"}).HasVaultImportIdentity() {
		t.Fatal("import AppRole must count as import identity")
	}
	if (Config{VaultImportRoleID: "r"}).HasVaultImportIdentity() {
		t.Fatal("role_id alone is not an import identity")
	}
}

func TestResolveVaultImportAuthMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "explicit import method", cfg: Config{VaultImportAuthMethod: "approle", VaultAuthMethod: "token"}, want: "approle"},
		{name: "only import token defaults to token", cfg: Config{VaultImportToken: "hvs.import", VaultAuthMethod: "approle"}, want: "token"},
		{name: "only import approle defaults to approle", cfg: Config{VaultImportRoleID: "r", VaultImportSecretID: "s", VaultAuthMethod: "token"}, want: "approle"},
		{name: "inherit read method", cfg: Config{VaultAuthMethod: "approle", VaultImportToken: "t", VaultImportRoleID: "r", VaultImportSecretID: "s"}, want: "approle"},
		{name: "empty defaults to token", cfg: Config{}, want: "token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.cfg.ResolveVaultImportAuthMethod(); got != tt.want {
				t.Fatalf("ResolveVaultImportAuthMethod = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadReadsAuthModeAndStaticTokens(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("CLM_AUTH_MODE", "static_token")
	t.Setenv("CLM_STATIC_TOKENS", "viewer:tok_v,platform_admin:tok_p,inventory:tok_inv")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthMode != "static_token" {
		t.Fatalf("AuthMode = %q, want static_token", cfg.AuthMode)
	}
	if cfg.StaticTokens["viewer"] != "tok_v" || cfg.StaticTokens["platform_admin"] != "tok_p" || cfg.StaticTokens["inventory"] != "tok_inv" {
		t.Fatalf("StaticTokens = %#v", cfg.StaticTokens)
	}
}

func TestLoadEmptyAuthModeIsStaticToken(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("CLM_AUTH_MODE", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthMode != "static_token" {
		t.Fatalf("AuthMode = %q, want static_token", cfg.AuthMode)
	}
}

func TestLoadRejectsUnknownAuthMode(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("CLM_AUTH_MODE", "oidc")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown CLM_AUTH_MODE")
	}
	if !strings.Contains(err.Error(), "CLM_AUTH_MODE") {
		t.Fatalf("expected CLM_AUTH_MODE in error, got %v", err)
	}
}

func TestLoadParsesHashedStaticToken(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("CLM_STATIC_TOKENS", "viewer:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.StaticTokens["viewer"]
	if got != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("StaticTokens[viewer] = %q", got)
	}
}

func TestLoadRejectsUnknownStaticTokenRole(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/clm")
	t.Setenv("CLM_STATIC_TOKENS", "superuser:tok_x")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown static token role")
	}
	if !strings.Contains(err.Error(), "superuser") {
		t.Fatalf("expected role in error, got %v", err)
	}
}

func TestLookupStaticRoleMatchesPlainAndHashed(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cret"))
	cfg := Config{StaticTokens: map[string]string{
		"viewer":         "tok_v",
		"platform_admin": "sha256:" + hex.EncodeToString(sum[:]),
	}}
	if role, ok := cfg.LookupStaticRole("tok_v"); !ok || role != "viewer" {
		t.Fatalf("plain lookup = %q %v, want viewer true", role, ok)
	}
	if role, ok := cfg.LookupStaticRole("s3cret"); !ok || role != "platform_admin" {
		t.Fatalf("hashed lookup = %q %v, want platform_admin true", role, ok)
	}
	if _, ok := cfg.LookupStaticRole("nope"); ok {
		t.Fatal("unknown token must not match")
	}
	if _, ok := cfg.LookupStaticRole(""); ok {
		t.Fatal("empty token must not match")
	}
}

func TestAuthPostureWarnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantSub []string
		wantLen int
	}{
		{
			name: "insecure hatch warns",
			cfg:  Config{InsecureNoAuth: true, AuthMode: "static_token", StaticTokens: map[string]string{"platform_admin": "tok"}},
			wantSub: []string{
				"CLM_INSECURE_NO_AUTH",
				"platform_admin",
			},
			wantLen: 1,
		},
		{
			name: "empty static tokens without hatch warns",
			cfg:  Config{AuthMode: "static_token"},
			wantSub: []string{
				"CLM_STATIC_TOKENS",
				"401",
			},
			wantLen: 1,
		},
		{
			name: "empty auth mode treated as static_token with empty tokens warns",
			cfg:  Config{AuthMode: ""},
			wantSub: []string{
				"CLM_STATIC_TOKENS",
			},
			wantLen: 1,
		},
		{
			name:    "hatch true and empty tokens only hatch warning",
			cfg:     Config{InsecureNoAuth: true, AuthMode: "static_token"},
			wantSub: []string{"CLM_INSECURE_NO_AUTH"},
			wantLen: 1,
		},
		{
			name:    "configured static tokens no warning",
			cfg:     Config{AuthMode: "static_token", StaticTokens: map[string]string{"viewer": "tok_v"}},
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := AuthPostureWarnings(tt.cfg)
			if len(got) != tt.wantLen {
				t.Fatalf("AuthPostureWarnings = %#v, want len %d", got, tt.wantLen)
			}
			for _, sub := range tt.wantSub {
				found := false
				for _, msg := range got {
					if strings.Contains(msg, sub) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("AuthPostureWarnings = %#v, want substring %q", got, sub)
				}
			}
		})
	}
}
