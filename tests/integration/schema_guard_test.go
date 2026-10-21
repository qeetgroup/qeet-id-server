//go:build integration

package integration

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
)

// TestSchemaGuardRefusesANewerDatabase: rolling back to an older build after
// a later release migrated the database leaves a schema the build doesn't
// know. Start (migrations.Run) and the host's pre-switch check
// (CheckCompatible, `qeet-id-server schema-check`) must refuse it, changing
// nothing; a database at or behind the build's latest migration is fine, and
// a half-applied migration is refused with its recovery step. Before the fix
// Run failed with golang-migrate's "file does not exist", and nothing could
// tell before a restart.
func TestSchemaGuardRefusesANewerDatabase(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	dbName := "schemaguard_" + uniqueSlug("db")[len("db-"):]
	if _, err := testPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { _, _ = testPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") })
	u, err := url.Parse(testDSN)
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	u.Path = "/" + dbName
	dsn := u.String()

	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("migrate a fresh database: %v", err)
	}
	latest, err := migrations.Latest()
	if err != nil {
		t.Fatal(err)
	}
	st, err := migrations.CheckCompatible(dsn)
	if err != nil || st.Database != latest || st.Latest != latest || st.Dirty {
		t.Fatalf("current database: %+v, %v; want compatible at %d", st, err, latest)
	}
	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("restart on the same schema: %v", err)
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	setVersion := func(v uint, dirty bool) {
		t.Helper()
		if _, err := conn.Exec(ctx, "UPDATE schema_migrations SET version = $1, dirty = $2", int64(v), dirty); err != nil {
			t.Fatalf("set version: %v", err)
		}
	}

	// A later release ran one more migration.
	setVersion(latest+1, false)
	for name, err := range map[string]error{
		"start":        migrations.Run(dsn),
		"schema-check": func() error { _, err := migrations.CheckCompatible(dsn); return err }(),
	} {
		var schemaErr *migrations.SchemaError
		if !errors.As(err, &schemaErr) || !errors.Is(err, migrations.ErrSchemaNewer) || schemaErr.Database != latest+1 || schemaErr.Latest != latest {
			t.Fatalf("%s on a newer schema: %v, want ErrSchemaNewer naming %d and %d", name, err, latest+1, latest)
		}
	}
	var version int64
	var dirty bool
	if err := conn.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&version, &dirty); err != nil || uint(version) != latest+1 || dirty {
		t.Fatalf("after the refusal: version %d dirty %v (%v); want %d untouched", version, dirty, err, latest+1)
	}

	// A migration that failed part-way.
	setVersion(latest, true)
	if _, err := migrations.CheckCompatible(dsn); !errors.Is(err, migrations.ErrSchemaDirty) {
		t.Fatalf("schema-check on a dirty schema: %v, want ErrSchemaDirty", err)
	}
	if err := migrations.Run(dsn); !errors.Is(err, migrations.ErrSchemaDirty) {
		t.Fatalf("start on a dirty schema: %v, want ErrSchemaDirty", err)
	}
}
