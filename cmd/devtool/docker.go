package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// testDB runs every test, the database ones too, with the race detector, against one throwaway
// PostgreSQL: the first package migrates a template database and each gets a copy
// (internal/platform/database/dbtest). The container goes whatever happens.
func testDB() error {
	name := fmt.Sprintf("qeet-id-dbtest-%d", os.Getpid())
	password := envOr("DBTEST_POSTGRES_PASSWORD", "postgres")
	if err := run("docker", "run", "-d", "--rm", "--name", name, "-e", "POSTGRES_PASSWORD="+password, "-p", "127.0.0.1::5432",
		envOr("DBTEST_POSTGRES_IMAGE", "postgres:16-alpine"), "-c", "max_connections="+envOr("DBTEST_MAX_CONNECTIONS", "400"),
		"-c", "fsync=off", "-c", "synchronous_commit=off"); err != nil {
		return err
	}
	defer func() { _, _ = output("docker", "stop", name) }()
	port, err := waitForPostgres(name)
	if err != nil {
		return err
	}
	env := []string{"DBTEST_SERVER=postgres://postgres:" + password + "@127.0.0.1:" + port + "/postgres?sslmode=disable"}
	return runIn("", env, os.Stdout, "go", "test", "-race", "-tags", "integration", "-count=1", "-timeout", envOr("TEST_TIMEOUT", "15m"), "./...")
}

// waitForPostgres waits until container name's PostgreSQL accepts connections (its second "ready",
// after the init restart) and returns its published host port.
func waitForPostgres(name string) (string, error) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		logs, _ := combined("docker", "logs", name)
		if strings.Count(logs, "ready to accept connections") >= 2 {
			break
		}
		if time.Now().After(deadline) {
			return "", errors.New("PostgreSQL did not start within 90s")
		}
		time.Sleep(200 * time.Millisecond)
	}
	mapped, err := output("docker", "port", name, "5432/tcp")
	if err != nil {
		return "", err
	}
	first, _, _ := strings.Cut(mapped, "\n")
	return first[strings.LastIndex(first, ":")+1:], nil
}

// combined returns name's standard output and error together.
func combined(name string, args ...string) (string, error) {
	var buf strings.Builder
	err := runIn("", nil, &buf, name, args...)
	return buf.String(), err
}

func dbReset() error {
	if err := run("docker", "compose", "down", "-v"); err != nil {
		return err
	}
	return run("docker", "compose", "up", "-d")
}

func seedReset() error {
	if err := dbReset(); err != nil {
		return err
	}
	if err := run("docker", "compose", "up", "-d", "--wait"); err != nil {
		return err
	}
	return run("go", "run", "./cmd/seed")
}

// obsServices are the local observability stack's services (docker-compose.yml, profile observability).
var obsServices = []string{"otel-collector", "prometheus", "alertmanager", "loki", "tempo", "pyroscope", "alloy", "grafana", "postgres-exporter", "blackbox-exporter"}

func obsUp() error {
	if err := os.MkdirAll(filepath.Join("bin", "logs"), 0o750); err != nil {
		return err
	}
	if err := run("docker", append([]string{"compose", "--profile", "observability", "up", "-d"}, obsServices...)...); err != nil {
		return err
	}
	fmt.Printf("Grafana http://localhost:%s · Prometheus http://localhost:%s · Alertmanager http://localhost:%s · Pyroscope http://localhost:%s · alert mail http://localhost:%s\n",
		envOr("GRAFANA_PORT", "3300"), envOr("PROMETHEUS_PORT", "9090"), envOr("ALERTMANAGER_PORT", "9093"), envOr("PYROSCOPE_PORT", "4040"), envOr("MAILPIT_UI_PORT", "8025"))
	return nil
}

// obsDown stops only the observability services, never the database.
func obsDown() error {
	return run("docker", append([]string{"compose", "--profile", "observability", "stop"}, obsServices...)...)
}

// migrateDown rolls one migration back with the migrate CLI, to try its down file. The server applies
// migrations at start and records the files; one applied by the migrate tool is refused.
func migrateDown() error {
	url := envOr("DB_URL", "postgres://"+envOr("POSTGRES_USER", "postgres")+":"+envOr("POSTGRES_PASSWORD", "password")+
		"@localhost:"+envOr("POSTGRES_PORT", "5001")+"/"+envOr("POSTGRES_DB", "qeet_id")+"?sslmode=disable")
	return run("migrate", "-path", filepath.FromSlash("internal/platform/database/migrations"), "-database", url, "down", "1")
}

// killPort stops whatever listens on port: netstat on Windows, lsof elsewhere.
func killPort(port string) error {
	var pids []int
	if runtime.GOOS == "windows" {
		out, _ := output("netstat", "-ano", "-p", "TCP")
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 5 && strings.HasSuffix(f[1], ":"+port) && strings.EqualFold(f[3], "LISTENING") {
				if pid, err := strconv.Atoi(f[4]); err == nil {
					pids = append(pids, pid)
				}
			}
		}
	} else {
		out, _ := output("lsof", "-nP", "-iTCP:"+port, "-sTCP:LISTEN", "-t")
		for _, f := range strings.Fields(out) {
			if pid, err := strconv.Atoi(f); err == nil {
				pids = append(pids, pid)
			}
		}
	}
	if len(pids) == 0 {
		fmt.Printf(":%s not running\n", port)
		return nil
	}
	for _, pid := range pids {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	}
	fmt.Printf("stopped :%s\n", port)
	return nil
}
