// Command migrate wraps the golang-migrate CLI (which must be on PATH), reading
// DB_URL from the environment and forwarding structured exit codes for use in
// Kubernetes init containers and Docker Compose one-shots.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
)

const migrationsPath = "internal/platform/database/migrations"

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

	args, env, err := childArgs(dbURL, subcmd, extraArgs)
	if err != nil {
		slog.Error("invalid DB_URL", "err", err)
		os.Exit(1)
	}

	slog.Info("running migrate", "cmd", subcmd, "path", migrationsPath, "extra_args", extraArgs)

	cmd := exec.Command(migrateBin, args...) // #nosec G204 G702 -- operator CLI; argument list, no shell
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintf(os.Stderr, "migrate exited with code %d\n", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		slog.Error("migrate run failed", "err", err)
		os.Exit(1)
	}
}

// childArgs returns the migrate CLI arguments and extra environment. Any
// password in dbURL, in its user information or a password parameter, moves to
// PGPASSWORD, which the CLI's Postgres drivers read, so it does not appear in
// the child's command line. The parameter wins, as it does for the drivers.
func childArgs(dbURL, subcmd string, extraArgs []string) (args, env []string, err error) {
	u, err := url.Parse(dbURL)
	if err != nil || u.Scheme == "" {
		return nil, nil, errors.New("DB_URL must be a URL such as postgres://user@host:5432/db")
	}
	password, found := u.User.Password()
	if found {
		u.User = url.User(u.User.Username())
	}
	if q := u.Query(); q.Has("password") {
		password, found = q.Get("password"), true
		q.Del("password")
		u.RawQuery = q.Encode()
	}
	if found {
		env = append(env, "PGPASSWORD="+password)
	}
	args = append([]string{"-path", migrationsPath, "-database", u.String(), subcmd}, extraArgs...)
	return args, env, nil
}
