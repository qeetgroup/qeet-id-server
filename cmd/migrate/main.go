// Command migrate wraps the golang-migrate CLI (which must be on PATH), reading
// DB_URL from the environment and forwarding structured exit codes for use in
// Kubernetes init containers and Docker Compose one-shots.
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
