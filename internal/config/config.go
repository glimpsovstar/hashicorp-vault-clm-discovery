package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Addr              string        `envconfig:"ADDR" default:":8080"`
	DatabaseURL       string        `envconfig:"DATABASE_URL" required:"true"`
	ExpiringSoonDays  int           `envconfig:"EXPIRING_SOON_DAYS" default:"30"`
	ScanTimeout       time.Duration `envconfig:"SCAN_TIMEOUT" default:"5s"`
	DefaultConcurrency int          `envconfig:"DEFAULT_CONCURRENCY" default:"50"`
	AllowPrivateRanges bool         `envconfig:"ALLOW_PRIVATE_RANGES" default:"false"`
	CORSOrigins       []string      `envconfig:"CORS_ORIGINS" default:"http://localhost:3000"`
	LogLevel          string        `envconfig:"LOG_LEVEL" default:"info"`
}

func Load() (Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	return cfg, err
}
