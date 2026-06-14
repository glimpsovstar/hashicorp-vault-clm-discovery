package logging

import (
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"trace", LevelTrace},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
	}

	for _, tc := range tests {
		got := ParseLevel(tc.input).(slog.Level)
		if got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestIsDebugOrTrace(t *testing.T) {
	if !IsDebugOrTrace("debug") || !IsDebugOrTrace("trace") {
		t.Fatal("expected debug/trace to be verbose")
	}
	if IsDebugOrTrace("info") || IsDebugOrTrace("error") {
		t.Fatal("expected info/error to be non-verbose")
	}
}

func TestNewRespectsLevel(t *testing.T) {
	log := New("error")
	if log.Enabled(nil, slog.LevelInfo) {
		t.Fatal("error-level logger should not emit info")
	}
	if !log.Enabled(nil, slog.LevelError) {
		t.Fatal("error-level logger should emit error")
	}
}
