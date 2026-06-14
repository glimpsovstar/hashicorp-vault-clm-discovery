package logging

import (
	"log/slog"
	"os"
	"strings"
)

// LevelTrace is below slog.LevelDebug for per-target probe tracing.
const LevelTrace = slog.Level(-8)

// New creates a JSON slog logger with the given level string (info, debug, trace, warn, error).
func New(level string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: ParseLevel(level),
	}))
}

// ParseLevel maps LOG_LEVEL strings to slog levels. Unknown values default to info.
func ParseLevel(level string) slog.Leveler {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace":
		return LevelTrace
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// IsDebugOrTrace reports whether verbose scan diagnostics should be logged.
func IsDebugOrTrace(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace", "debug":
		return true
	default:
		return false
	}
}

// IsTrace reports whether per-target probe tracing should be logged.
func IsTrace(level string) bool {
	return strings.EqualFold(strings.TrimSpace(level), "trace")
}
