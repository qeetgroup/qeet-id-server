//go:build integration

// Package integration runs domain flows against a real, ephemeral Postgres
// spun up via testcontainers and migrated with the repo's own migration files.
// It is gated behind the `integration` build tag so the default `go test ./...`
// stays Docker-free; run it with `make test-integration`. If Docker isn't
// reachable the suite skips rather than fails.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testPool is the shared pool for the whole package; nil means setup was
// skipped (no Docker), in which case requireDB skips each test.
var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx := context.Background()

	// Ryuk (testcontainers' reaper) can't be reached on some macOS/colima
	// Docker setups and then blocks startup indefinitely. We clean up
	// explicitly via defer ctr.Terminate, so disable it for a hang-free run.
	if os.Getenv("TESTCONTAINERS_RYUK_DISABLED") == "" {
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}

	scripts, err := upMigrations()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: cannot locate migrations: %v\n", err)
		return 1
	}

	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("qeet_id_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		tcpostgres.WithInitScripts(scripts...),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		// No Docker / can't start a container: skip rather than fail so the
		// suite is safe to run anywhere.
		fmt.Fprintf(os.Stderr, "integration: skipping (container start failed): %v\n", err)
		return 0
	}
	defer func() { _ = ctr.Terminate(ctx) }()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: connection string: %v\n", err)
		return 1
	}
	testPool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: pool: %v\n", err)
		return 1
	}
	defer testPool.Close()

	return m.Run()
}

// upMigrations returns the absolute paths of every *.up.sql migration, sorted
// so Postgres' init-script runner applies them in version order.
func upMigrations() ([]string, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, filepath.Join(dir, e.Name()))
		}
	}
	if len(ups) == 0 {
		return nil, fmt.Errorf("no .up.sql files in %s", dir)
	}
	sort.Strings(ups)
	return ups, nil
}

// requireDB skips the calling test when no container is available.
func requireDB(t *testing.T) {
	t.Helper()
	if testPool == nil {
		t.Skip("integration: no database (Docker unavailable)")
	}
}

// uniqueSlug returns a short, collision-resistant identifier for test data.
func uniqueSlug(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
}

// createTenant inserts a bare tenant row and returns its id.
func createTenant(t *testing.T, ctx context.Context, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := testPool.QueryRow(ctx, `
		INSERT INTO tenant.tenants (slug, name, plan, region)
		VALUES ($1, $2, 'free', 'us-east-1') RETURNING id
	`, slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("createTenant: %v", err)
	}
	return id
}
