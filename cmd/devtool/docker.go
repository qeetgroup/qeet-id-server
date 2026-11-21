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

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
)

// testDB runs every test, the database ones too, with the race detector.
func testDB() error { return testDBWith() }

// testDBWith runs every test with the go test flags in extra, against one throwaway PostgreSQL: the
// first package migrates a template database and each gets a copy (internal/platform/database/dbtest).
// The container goes whatever happens.
func testDBWith(extra ...string) error {
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
	args := append([]string{"test", "-race", "-tags", "integration", "-count=1", "-timeout", envOr("TEST_TIMEOUT", "15m")}, extra...)
	return runIn("", env, os.Stdout, "go", append(args, "./...")...)
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

// k6Image is the pinned k6 that runs the load test; K6_IMAGE overrides it.
func k6Image() string {
	return envOr("K6_IMAGE", "grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8")
}

// loadTest runs tests/load/load.js against a running local server (make dev) with k6 in Docker, and
// writes its summary to bin/reports/load-summary.json. LOAD_BASE_URL and LOAD_DURATION override
// where and how long; it fails when a service level objective is missed.
func loadTest() error {
	dir, err := repoDir()
	if err != nil {
		return err
	}
	reports := filepath.Join(dir, "bin", "reports")
	if err := reportsDir(reports); err != nil {
		return err
	}
	base := envOr("LOAD_BASE_URL", "http://host.docker.internal:"+envOr("HTTP_PORT", "4001"))
	return run("docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
		"-v", filepath.Join(dir, "tests", "load")+":/scripts:ro", "-v", reports+":/reports",
		"-e", "BASE_URL="+base, "-e", "DURATION="+envOr("LOAD_DURATION", "1m"),
		k6Image(), "run", "--summary-export=/reports/load-summary.json", "/scripts/load.js")
}

// The pinned SonarQube scanner; SONAR_SCANNER_IMAGE overrides it.
func sonarScannerImage() string {
	return envOr("SONAR_SCANNER_IMAGE", "sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1@sha256:38207bba3d98c8ce6f6c051ea2b9f05a24480da78c9ee5945ceafc3d9de02b88")
}

func sonarUp() error {
	if err := run("docker", "compose", "--profile", "sonar", "up", "-d", "sonarqube"); err != nil {
		return err
	}
	fmt.Printf("SonarQube http://localhost:%s (first sign-in admin / admin; it starts in about a minute). "+
		"Create a token under My Account › Security, set SONAR_TOKEN in .env, then run make sonar.\n", envOr("SONAR_PORT", "9000"))
	return nil
}

func sonarDown() error { return run("docker", "compose", "--profile", "sonar", "stop", "sonarqube") }

// sonar runs every test, the database ones too, for coverage across packages, then the SonarQube
// scanner (Docker) over the repository with sonar-project.properties. SONAR_TOKEN is passed to the
// scanner by name, never on its command line.
func sonar() error {
	if os.Getenv("SONAR_TOKEN") == "" {
		return errors.New("SONAR_TOKEN is unset: create a token in SonarQube (My Account › Security) and set it in .env")
	}
	dir, err := repoDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin", "reports"), 0o750); err != nil {
		return err
	}
	// Most tests here need the database, and many reach code in other packages (the journeys in tests/),
	// so coverage counts them all, against every package.
	if err := testDBWith("-coverprofile="+filepath.Join("bin", "reports", "coverage.out"), "-coverpkg=./..."); err != nil {
		return err
	}
	host := envOr("SONAR_HOST_URL", "http://host.docker.internal:"+envOr("SONAR_PORT", "9000"))
	return run("docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
		"-e", "SONAR_HOST_URL="+host, "-e", "SONAR_TOKEN", "-v", dir+":/usr/src", sonarScannerImage())
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

// localDBURL is the local database: DB_URL, else one built from the docker compose settings.
func localDBURL() string {
	return envOr("DB_URL", "postgres://"+envOr("POSTGRES_USER", "postgres")+":"+envOr("POSTGRES_PASSWORD", "password")+
		"@localhost:"+envOr("POSTGRES_PORT", "5001")+"/"+envOr("POSTGRES_DB", "qeet_id")+"?sslmode=disable")
}

// migrateUp applies every pending migration without starting the server. It uses the server's own
// runner, as make dev and make seed do at start, so the files it applies are recorded and the server
// accepts the database afterwards; the migrate CLI keeps no such record.
func migrateUp() error {
	url := localDBURL()
	before, err := migrations.Read(url)
	if err != nil {
		return fmt.Errorf("%w\nIs the local database running? Start it with make db-up", err)
	}
	if err := migrations.Run(url); err != nil {
		return err
	}
	after, err := migrations.Read(url)
	if err != nil {
		return err
	}
	switch after.Database - before.Database {
	case 0:
		fmt.Printf("Nothing to apply: the database is up to date, at migration %04d.\n", after.Database)
	case 1:
		fmt.Printf("Applied migration %04d: the database is up to date.\n", after.Database)
	default:
		fmt.Printf("Applied migrations %04d to %04d: the database is up to date.\n", before.Database+1, after.Database)
	}
	return nil
}

// migrateDown rolls one migration back with the migrate CLI, to try its down file. Apply it again with
// migrateUp (or make dev), never the migrate CLI: the server refuses a database that keeps no record of
// the files that built it.
func migrateDown() error {
	return run("migrate", "-path", filepath.FromSlash("internal/platform/database/migrations"), "-database", localDBURL(), "down", "1")
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
