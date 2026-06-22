package config

import (
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
}
