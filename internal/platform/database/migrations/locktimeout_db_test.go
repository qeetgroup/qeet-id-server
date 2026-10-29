//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
)

// TestMigrationsGiveUpOnABusyTable checks that a migration waiting for a table
// another connection holds fails once its lock timeout passes, rather than
// queueing every query to that table behind it.
func TestMigrationsGiveUpOnABusyTable(t *testing.T) {
	ctx := dbtest.Context(t)
	*migrations.LockTimeout = "300ms"
	t.Cleanup(func() { *migrations.LockTimeout = "10s" })
	holder, err := dbtest.Owner(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if _, err := holder.Exec(ctx, `LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := migrations.Run(dbtest.DSN(t)); err == nil {
		t.Error("a migration behind a held table succeeded")
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("a migration waited %s for a held table, want about its lock timeout", waited)
	}
}
