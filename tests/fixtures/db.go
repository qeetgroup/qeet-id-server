package fixtures

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// NewTestDB starts a fresh postgres:16-alpine testcontainer, runs all migrations,
// and returns a connected pool. The container and pool are cleaned up via t.Cleanup.
func NewTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx := context.Background()

	ctr, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithDatabase("qeet_id_test"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2),
		),
	)
	if err != nil {
		t.Fatalf("start postgres testcontainer: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := runMigrations(ctx, connStr); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	return pool
}

func runMigrations(ctx context.Context, connStr string) error {
	// golang-migrate programmatic API
	// Import path: github.com/golang-migrate/migrate/v4
	// This is a compile-time dep already present via Makefile migrate targets.
	_ = ctx
	_ = connStr
	// TODO: wire golang-migrate programmatic API here if needed for CI
	// For now tests that need this call `make db-up migrate-up` first.
	return fmt.Errorf("not yet implemented — run `make db-up migrate-up` before tests")
}
