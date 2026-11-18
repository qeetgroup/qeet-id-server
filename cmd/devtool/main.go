// Command devtool runs the development tasks the Makefile names (make dev is go run ./cmd/devtool
// dev), in Go, so they behave the same on Windows, macOS and Linux: no shell, openssl, sed or lsof
// is needed, only Go and Docker. Run it from the repository root; `devtool help` lists the tasks.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// task is one development task: what it does, and how.
type task struct {
	help string
	run  func(args []string) error
}

var tasks map[string]task

func init() {
	tasks = map[string]task{
		"install":       {"download the Go modules", func([]string) error { return run("go", "mod", "download") }},
		"dev-secrets":   {"generate the persistent local JWT and SAML signing keys into .secrets/", func([]string) error { return devSecrets() }},
		"dev":           {"run the API on :4001 with the local signing keys", func([]string) error { return dev(false) }},
		"dev-observed":  {"run the API with JSON logs to bin/logs/api.log and traces to the local collector", func([]string) error { return dev(true) }},
		"build":         {"build bin/qeet-id", func([]string) error { return run("go", "build", "-o", exe("bin/qeet-id"), "./cmd/api") }},
		"test":          {"run the tests that need no database", func([]string) error { return run("go", "test", "./...") }},
		"test-db":       {"run every test, the database ones too, with the race detector (needs Docker)", func([]string) error { return testDB() }},
		"lint":          {"go vet and golangci-lint, as CI runs them", func([]string) error { return lint() }},
		"sqlc":          {"regenerate every dbgen/ from its queries.sql", func([]string) error { return sqlcRun("generate") }},
		"sqlc-check":    {"fail if a dbgen/ is stale or a queries.sql isn't listed in sqlc.yaml", func([]string) error { return sqlcCheck() }},
		"fmt":           {"format every file: Go (gofmt, goimports), JavaScript, JSON, YAML and Markdown (Prettier), shell (shfmt)", func([]string) error { return formatAll() }},
		"fmt-check":     {"fail if a file isn't formatted, showing what make fmt would change", func([]string) error { return formatCheck() }},
		"openapi":       {"rebuild the API documents from api/openapi/src, and their Postman collection (needs Bun)", func([]string) error { return openapiBuild() }},
		"openapi-check": {"lint the API sources and fail if a built document or the Postman collection is out of date", func([]string) error { return openapiCheck() }},
		"postman":       {"rebuild the Postman collection in api/postman from the API documents", func([]string) error { return postman() }},
		"vuln":          {"govulncheck over what ships", func([]string) error { return vuln() }},
		"sast":          {"gosec, as CI configures it", func([]string) error { return sast() }},
		"secrets":       {"gitleaks over the git history and the working tree (Docker)", func([]string) error { return secretScan() }},
		"scan-image":    {"build the server image and scan it and the Dockerfile with Trivy (Docker)", func([]string) error { return scanImage() }},
		"ci":            {"the full local gate: build, test-db, lint, fmt-check, sqlc-check, openapi-check, vuln, sast, secrets", func([]string) error { return ci() }},
		"db-up":         {"start PostgreSQL, NATS and Mailpit", func([]string) error { return run("docker", "compose", "up", "-d") }},
		"db-down":       {"stop PostgreSQL, NATS and Mailpit", func([]string) error { return run("docker", "compose", "down") }},
		"db-reset":      {"recreate them with empty volumes", func([]string) error { return dbReset() }},
		"obs-up":        {"start the local observability stack (Grafana http://localhost:3300)", func([]string) error { return obsUp() }},
		"obs-down":      {"stop the observability stack (the database stays up)", func([]string) error { return obsDown() }},
		"migrate-down":  {"roll one migration back with the migrate CLI", func([]string) error { return migrateDown() }},
		"seed":          {"fill an empty local database with demo data", func([]string) error { return run("go", "run", "./cmd/seed") }},
		"seed-reset":    {"db-reset, wait for it, then seed", func([]string) error { return seedReset() }},
		"kill":          {"stop whatever listens on the API's port (HTTP_PORT, default 4001)", func([]string) error { return killPort(envOr("HTTP_PORT", "4001")) }},
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" {
		usage()
		return
	}
	t, ok := tasks[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "devtool: no task %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err := loadDotEnv(".env"); err != nil {
		fail(err)
	}
	if err := t.run(os.Args[2:]); err != nil {
		fail(err)
	}
}

func usage() {
	names := make([]string, 0, len(tasks))
	for n := range tasks {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Println("usage: go run ./cmd/devtool <task>   (or: make <task>)")
	for _, n := range names {
		fmt.Printf("  %-14s %s\n", n, tasks[n].help)
	}
}

func fail(err error) {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	fmt.Fprintln(os.Stderr, "devtool:", err)
	os.Exit(1)
}

// loadDotEnv sets each KEY=VALUE of path that the environment doesn't already set, as the Makefile's
// `include .env` + `export` did. A missing file is fine.
func loadDotEnv(path string) error {
	f, err := os.Open(path) // #nosec G304 -- the repository's own .env, by its fixed name
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, value, ok := strings.Cut(line, "=")
		if !ok || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, set := os.LookupEnv(key); !set {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}
