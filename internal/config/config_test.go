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
	"CLM_CONNECTIONS_KEY",
	"CLM_INSECURE_NO_AUTH",
	"CLM_AUTH_MODE",
	"CLM_STATIC_TOKENS",
	"VAULT_ROLE_ID",
	"VAULT_SECRET_ID",
	"VAULT_AUTH_METHOD",
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
