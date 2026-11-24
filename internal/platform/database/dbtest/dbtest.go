//go:build integration

// Package dbtest runs a package's database tests against a disposable PostgreSQL 16 database migrated
// with this repository's migrations. With DBTEST_SERVER set (make test-db starts one), each test
// package gets its own copy of a database migrated once per run; otherwise it starts a container.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

const (
	maxConns    = 4                // small, so a leaked or nested connection fails fast
	testTimeout = 30 * time.Second // per-test deadline; see Context
)

var (
	pool    *pgxpool.Pool
	dsn     string
	skipped string // why there is no database, when there is none
)

// Main starts PostgreSQL, applies every migration, runs the package's tests and
// exits. Call it from TestMain. Without Docker the tests skip, except under CI,
// where they fail.
func Main(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if server := os.Getenv("DBTEST_SERVER"); server != "" {
		return runShared(m, server)
	}
	ctx := context.Background()
	// Ryuk, the testcontainers reaper, hangs on some macOS Docker setups; the
	// container is terminated explicitly below instead.
	if os.Getenv("TESTCONTAINERS_RYUK_DISABLED") == "" {
		_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}
	tclog.SetDefault(tclog.NewNoopLogger())

	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("qeet_id_test"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if ctr != nil {
		defer func() { _ = ctr.Terminate(context.Background()) }()
	}
	if err != nil {
		if os.Getenv("CI") != "" {
			fmt.Fprintf(os.Stderr, "dbtest: start PostgreSQL: %v\n", err)
			return 1
		}
		skipped = fmt.Sprintf("dbtest: no database (start PostgreSQL: %v)", err)
		return m.Run()
	}

	dsn, err = ctr.ConnectionString(ctx, "sslmode=disable")
	if err == nil {
		err = migrations.Run(dsn)
	}
	if err == nil {
		pool, err = postgres.NewPool(ctx, dsn, 0, maxConns)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: %v\n", err)
		return 1
	}
	defer pool.Close()
	return m.Run()
}

// runShared runs the package's tests on its own copy of the run's template
// database on server, a postgres:// URL to its maintenance database, and drops
// the copy after.
func runShared(m *testing.M, server string) int {
	ctx := context.Background()
	name, err := copyTemplate(ctx, server)
	if err == nil {
		dsn, err = withDatabase(server, name)
	}
	if err == nil {
		pool, err = postgres.NewPool(ctx, dsn, 0, maxConns)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: %v\n", err)
		return 1
	}
	defer dropDatabase(server, name)
	defer pool.Close()
	return m.Run()
}

// templateLock serialises the packages of a run making their copies, so the
// first migrates the template while the rest wait.
const templateLock = 7346001

// copyTemplate creates a database for one package from the run's template,
// migrating the template first if no package has, and returns its name.
func copyTemplate(ctx context.Context, server string) (string, error) {
	conn, err := pgx.Connect(ctx, server)
	if err != nil {
		return "", fmt.Errorf("connect to DBTEST_SERVER: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, templateLock); err != nil {
		return "", err
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, templateLock) }()

	// Named for the migrations' contents, so an edited migration never reuses
	// a template built before the edit.
	fingerprint, err := migrations.Fingerprint()
	if err != nil {
		return "", err
	}
	template := "dbtest_template_" + fingerprint
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, template).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		if _, err := conn.Exec(ctx, `CREATE DATABASE `+template); err != nil {
			return "", err
		}
		templateDSN, err := withDatabase(server, template)
		if err != nil {
			return "", err
		}
		if err := migrations.Run(templateDSN); err != nil {
			_, _ = conn.Exec(ctx, `DROP DATABASE `+template+` WITH (FORCE)`)
			return "", fmt.Errorf("migrate the template: %w", err)
		}
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	name := "dbtest_" + hex.EncodeToString(suffix)
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+name+` TEMPLATE `+template); err != nil {
		return "", fmt.Errorf("copy the template: %w", err)
	}
	return name, nil
}

// withDatabase is server's URL naming database name instead.
func withDatabase(server, name string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("DBTEST_SERVER: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// dropDatabase drops a package's copy once its tests are done. Best effort:
// the server goes when the run ends.
func dropDatabase(server, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, server)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	_, _ = conn.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
}

// Pool returns the package's shared pool, skipping t when there is no database.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	if pool == nil {
		t.Skip(skipped)
	}
	return pool
}

// DSN returns the database's connection string, skipping t when there is none.
func DSN(t testing.TB) string {
	t.Helper()
	Pool(t)
	return dsn
}

// Owner returns a connection as the database's owner, outside the pool and its
// row-level security, for a test that changes the schema. It closes when t
// ends.
func Owner(t testing.TB) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(Context(t), DSN(t))
	if err != nil {
		t.Fatalf("dbtest: connect as owner: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// Context returns a context that ends when t does or after 30 seconds, so a
// test waiting on an exhausted pool fails instead of hanging.
func Context(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(func() {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("dbtest: test exceeded its %s deadline", testTimeout)
		}
		cancel()
	})
	return ctx
}

// LeaveOneConnection holds all but one of the shared pool's connections until
// t ends, so code that needs a second connection while it holds a transaction
// waits until its context ends.
func LeaveOneConnection(t testing.TB) {
	t.Helper()
	p := Pool(t)
	for range p.Config().MaxConns - 1 {
		conn, err := p.Acquire(Context(t))
		if err != nil {
			t.Fatalf("dbtest: hold a connection: %v", err)
		}
		t.Cleanup(conn.Release)
	}
}
