// Command migrate is a thin wrapper around the golang-migrate CLI that
// reads the database URL from the environment (same as the server) and
// provides structured exit codes for use in Kubernetes init containers
// and Docker Compose one-shots.
//
// The migrate CLI binary must be on PATH. Install it with:
//
//	brew install golang-migrate   # macOS
//	go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest
//
// Usage:
//
//	qeet-id-migrate              # apply all pending (default: up)
//	qeet-id-migrate up
//	qeet-id-migrate down 1
//	qeet-id-migrate version
//	qeet-id-migrate force N
//
// DB_URL is read from the environment (same as the server).
package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

const migrationsPath = "platform/database/migrations"

func main() {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		slog.Error("DB_URL is required")
		os.Exit(1)
	}

	// Locate the migrate CLI on PATH.
	migrateBin, err := exec.LookPath("migrate")
	if err != nil {
		slog.Error("migrate CLI not found on PATH",
			"hint", "brew install golang-migrate  OR  go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest")
		os.Exit(1)
	}

	subcmd := "up"
	var extraArgs []string
	if len(os.Args) > 1 {
		subcmd = os.Args[1]
		extraArgs = os.Args[2:]
	}

	args := []string{
		"-path", migrationsPath,
		"-database", dbURL,
		subcmd,
	}
	args = append(args, extraArgs...)

	slog.Info("running migrate", "cmd", subcmd, "path", migrationsPath, "extra_args", extraArgs)

	cmd := exec.Command(migrateBin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "migrate exited with code %d\n", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		slog.Error("migrate run failed", "err", err)
		os.Exit(1)
	}
}
