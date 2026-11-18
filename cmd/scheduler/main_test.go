package main

import (
	"context"
	"log/slog"
	"testing"
)

// TestSchedulerHonoursTheLogSettings checks that the scheduler sets up its
// logger from LOG_LEVEL and LOG_FORMAT, as the API does, so debug logging can
// be turned on for scheduled jobs.
func TestSchedulerHonoursTheLogSettings(t *testing.T) {
	defer slog.SetDefault(slog.Default())
	t.Setenv("SERVICE_ENV", "dev")
	t.Setenv("DB_URL", "postgres://localhost/unused")
	t.Setenv("LOG_FORMAT", "json")
	for level, debug := range map[string]bool{"debug": true, "warn": false} {
		t.Setenv("LOG_LEVEL", level)
		setUp()
		if got := slog.Default().Enabled(context.Background(), slog.LevelDebug); got != debug {
			t.Errorf("LOG_LEVEL=%s: debug logging %v, want %v", level, got, debug)
		}
		if got := slog.Default().Enabled(context.Background(), slog.LevelInfo); got == (level == "warn") {
			t.Errorf("LOG_LEVEL=%s: info logging %v", level, got)
		}
	}
}
