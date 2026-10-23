//go:build integration

// Package dbtest runs a package's database tests against a disposable
// PostgreSQL 16 container migrated with the repository's own migrations. Each
// test package starts one container from TestMain and shares it across tests.
package dbtest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	db "github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
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
		pool, err = db.NewPool(ctx, dsn, 0, maxConns)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: %v\n", err)
		return 1
	}
	defer pool.Close()
	return m.Run()
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
