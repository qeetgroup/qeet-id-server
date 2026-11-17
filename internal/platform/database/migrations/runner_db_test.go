//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
)

// emptyDatabase creates a database with nothing in it beside the package's
// own, dropped when t ends, and returns its URL.
func emptyDatabase(t *testing.T) string {
	t.Helper()
	owner := dbtest.Owner(t)
	name := "runner_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := owner.Exec(dbtest.Context(t), `CREATE DATABASE `+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`) })
	u, err := url.Parse(dbtest.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// carry makes the runner read the build's migrations as change leaves them,
// until t ends, and returns them.
func carry(t *testing.T, change func(files fstest.MapFS)) fstest.MapFS {
	t.Helper()
	built := *migrations.Source
	if _, swapped := built.(fstest.MapFS); !swapped {
		t.Cleanup(func() { *migrations.Source = built })
	}
	files := fstest.MapFS{}
	err := fs.WalkDir(built, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(built, path)
		files[path] = &fstest.MapFile{Data: raw}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	change(files)
	*migrations.Source = files
	return files
}

// refused fails t unless err says the database was built from other files,
// naming file and the way out.
func refused(t *testing.T, what string, err error, file string) {
	t.Helper()
	if !errors.Is(err, migrations.ErrSchemaChanged) {
		t.Fatalf("%s: %v, want %v", what, err, migrations.ErrSchemaChanged)
	}
	if msg := err.Error(); !strings.Contains(msg, file) || !strings.Contains(msg, "make db-reset") {
		t.Errorf("%s: %q, want it to name %s and make db-reset", what, msg, file)
	}
}

// exec runs sql on the database at dsn as its owner.
func exec(t *testing.T, dsn, sql string) {
	t.Helper()
	conn, err := pgx.Connect(dbtest.Context(t), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(dbtest.Context(t), sql); err != nil {
		t.Fatal(err)
	}
}

// TestADatabaseBuiltFromOtherFilesIsRefused checks that a build whose copy of
// an applied migration differs from the one that built the database neither
// migrates nor passes the check, and that the database's own build still does.
func TestADatabaseBuiltFromOtherFilesIsRefused(t *testing.T) {
	dsn := emptyDatabase(t)
	if err := migrations.Run(dsn); err != nil {
		t.Fatal(err)
	}
	built, err := migrations.CheckCompatible(dsn)
	if err != nil {
		t.Fatalf("the build that migrated the database: %v", err)
	}
	const edited = "0005_organization.up.sql"
	t.Run("an edited migration", func(t *testing.T) {
		carry(t, func(files fstest.MapFS) {
			files[edited] = &fstest.MapFile{Data: append([]byte("-- edited\n"), files[edited].Data...)}
			files[fmt.Sprintf("%04d_extra.up.sql", built.Latest+1)] = &fstest.MapFile{Data: []byte(`CREATE TABLE public.runner_extra (id INT);`)}
		})
		refused(t, "migrating", migrations.Run(dsn), edited)
		st, err := migrations.CheckCompatible(dsn)
		refused(t, "the check", err, edited)
		if st.Database != built.Database || st.Dirty {
			t.Errorf("the refused database reads %+v, want it left at migration %d", st, built.Database)
		}
	})
	if err := migrations.Run(dsn); err != nil {
		t.Errorf("the build that migrated the database, after another was refused: %v", err)
	}
}

// TestADatabaseMigratedByAnythingElseIsRefused checks that a database with
// migrations applied and no record of the files that applied them, as the
// migrate tool or an earlier build leaves it, is refused.
func TestADatabaseMigratedByAnythingElseIsRefused(t *testing.T) {
	dsn := emptyDatabase(t)
	if err := migrations.Run(dsn); err != nil {
		t.Fatal(err)
	}
	exec(t, dsn, `DELETE FROM public.schema_migration_checksums WHERE version = 3`)
	refused(t, "migrating with one record missing", migrations.Run(dsn), "0003_platform.up.sql")
	exec(t, dsn, `DROP TABLE public.schema_migration_checksums`)
	refused(t, "migrating with no records", migrations.Run(dsn), "0001_schemas_and_role.up.sql")
	_, err := migrations.CheckCompatible(dsn)
	refused(t, "the check with no records", err, "0001_schemas_and_role.up.sql")
	exec(t, dsn, `DO $$ BEGIN
		IF to_regclass('public.schema_migration_checksums') IS NOT NULL THEN
			RAISE EXCEPTION 'the refused database was changed: it has a table of records';
		END IF;
	END $$`)
}

// TestANewMigrationIsAppliedAndRecorded checks that a migration added on top
// is applied and from then on held to its contents, and that one rolled back
// can be changed and applied again.
func TestANewMigrationIsAppliedAndRecorded(t *testing.T) {
	dsn := emptyDatabase(t)
	if err := migrations.Run(dsn); err != nil {
		t.Fatal(err)
	}
	latest, err := migrations.Latest()
	if err != nil {
		t.Fatal(err)
	}
	up := fmt.Sprintf("%04d_extra.up.sql", latest+1)
	down := fmt.Sprintf("%04d_extra.down.sql", latest+1)
	with := func(sql string) func(fstest.MapFS) {
		return func(files fstest.MapFS) {
			files[up] = &fstest.MapFile{Data: []byte(sql)}
			files[down] = &fstest.MapFile{Data: []byte(`DROP TABLE public.runner_extra;`)}
		}
	}
	first := carry(t, with(`CREATE TABLE public.runner_extra (id INT);`))
	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("a new migration: %v", err)
	}
	if st, err := migrations.CheckCompatible(dsn); err != nil || st.Database != latest+1 {
		t.Fatalf("after a new migration: %+v, %v; want migration %d", st, err, latest+1)
	}
	if err := migrations.Run(dsn); err != nil {
		t.Errorf("starting again on the new migration: %v", err)
	}

	carry(t, with(`CREATE TABLE public.runner_extra (id INT, note TEXT);`))
	refused(t, "the new migration, edited after it was applied", migrations.Run(dsn), up)

	src, err := iofs.New(first, ".")
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Steps(-1)
	_, _ = m.Close()
	if err != nil {
		t.Fatalf("roll the new migration back: %v", err)
	}
	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("the new migration, edited after it was rolled back: %v", err)
	}
	if _, err := migrations.CheckCompatible(dsn); err != nil {
		t.Errorf("after applying the edited migration: %v", err)
	}
	exec(t, dsn, `INSERT INTO public.runner_extra (id, note) VALUES (1, 'the edited migration built this table')`)
}

// TestAWithdrawnMigrationLeavesNoRecord checks that a migration rolled back and
// then dropped from the build doesn't count as applied once a later one is.
func TestAWithdrawnMigrationLeavesNoRecord(t *testing.T) {
	dsn := emptyDatabase(t)
	if err := migrations.Run(dsn); err != nil {
		t.Fatal(err)
	}
	latest, err := migrations.Latest()
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := fmt.Sprintf("%04d_withdrawn", latest+1)
	first := carry(t, func(files fstest.MapFS) {
		files[withdrawn+".up.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE public.runner_withdrawn (id INT);`)}
		files[withdrawn+".down.sql"] = &fstest.MapFile{Data: []byte(`DROP TABLE public.runner_withdrawn;`)}
	})
	if err := migrations.Run(dsn); err != nil {
		t.Fatal(err)
	}
	src, err := iofs.New(first, ".")
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Steps(-1)
	_, _ = m.Close()
	if err != nil {
		t.Fatalf("roll the migration back: %v", err)
	}
	carry(t, func(files fstest.MapFS) {
		delete(files, withdrawn+".up.sql")
		delete(files, withdrawn+".down.sql")
		files[fmt.Sprintf("%04d_later.up.sql", latest+2)] = &fstest.MapFile{Data: []byte(`CREATE TABLE public.runner_later (id INT);`)}
	})
	for _, start := range []string{"the start that applies the later migration", "the start after it"} {
		if err := migrations.Run(dsn); err != nil {
			t.Fatalf("%s: %v", start, err)
		}
	}
	if _, err := migrations.CheckCompatible(dsn); err != nil {
		t.Errorf("the check after a withdrawn migration: %v", err)
	}
}

// busy holds table on the database at dsn until the returned func is called,
// and makes migrations give up waiting for it after 300ms until t ends.
func busy(t *testing.T, dsn, table string) (release func()) {
	t.Helper()
	*migrations.LockTimeout = "300ms"
	t.Cleanup(func() { *migrations.LockTimeout = "10s" })
	holder, err := pgx.Connect(dbtest.Context(t), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Close(context.Background()) })
	if _, err := holder.Exec(dbtest.Context(t), `BEGIN; LOCK TABLE `+table+` IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	return func() { _, _ = holder.Exec(context.Background(), `ROLLBACK`) }
}

// TestAMigrationThatGivesUpOnABusyTableRunsAgain checks that a migration which
// waited too long for a table leaves the database as it was, so the next start
// applies it, and that a concurrent index build is left for a person instead.
func TestAMigrationThatGivesUpOnABusyTableRunsAgain(t *testing.T) {
	for name, c := range map[string]struct {
		sql     string
		retried bool
	}{
		"an ordinary migration":    {`ALTER TABLE platform.incidents ADD COLUMN runner_probe INT;`, true},
		"a concurrent index build": {`CREATE INDEX CONCURRENTLY runner_probe_idx ON platform.incidents (id);`, false},
	} {
		t.Run(name, func(t *testing.T) {
			dsn := emptyDatabase(t)
			if err := migrations.Run(dsn); err != nil {
				t.Fatal(err)
			}
			built, err := migrations.CheckCompatible(dsn)
			if err != nil {
				t.Fatal(err)
			}
			carry(t, func(files fstest.MapFS) {
				files[fmt.Sprintf("%04d_probe.up.sql", built.Latest+1)] = &fstest.MapFile{Data: []byte(c.sql)}
			})
			release := busy(t, dsn, "platform.incidents")
			if err := migrations.Run(dsn); err == nil {
				t.Fatal("a migration behind a held table succeeded")
			}
			release()
			st, err := migrations.CheckCompatible(dsn)
			if !c.retried {
				if !errors.Is(err, migrations.ErrSchemaDirty) {
					t.Errorf("after the index build gave up: %+v, %v; want %v", st, err, migrations.ErrSchemaDirty)
				}
				return
			}
			if err != nil || st.Database != built.Database {
				t.Fatalf("after the migration gave up: %+v, %v; want migration %d and no refusal", st, err, built.Database)
			}
			if err := migrations.Run(dsn); err != nil {
				t.Fatalf("the next start, with the table free: %v", err)
			}
			if st, err := migrations.CheckCompatible(dsn); err != nil || st.Database != built.Latest+1 {
				t.Errorf("after the next start: %+v, %v; want migration %d", st, err, built.Latest+1)
			}
		})
	}
}

// TestAFailedMigrationIsRepaired checks the recovery of a half-applied
// migration: with the version put back, a repaired file is applied, and the
// migration that ran before it is still known by its record.
func TestAFailedMigrationIsRepaired(t *testing.T) {
	dsn := emptyDatabase(t)
	if err := migrations.Run(dsn); err != nil {
		t.Fatal(err)
	}
	latest, err := migrations.Latest()
	if err != nil {
		t.Fatal(err)
	}
	good, bad := fmt.Sprintf("%04d_good.up.sql", latest+1), fmt.Sprintf("%04d_bad.up.sql", latest+2)
	broken := carry(t, func(files fstest.MapFS) {
		files[good] = &fstest.MapFile{Data: []byte(`CREATE TABLE public.runner_good (id INT);`)}
		files[bad] = &fstest.MapFile{Data: []byte(`SELECT 1/0;`)}
	})
	if err := migrations.Run(dsn); err == nil {
		t.Fatal("a migration that divides by zero succeeded")
	}
	if _, err := migrations.CheckCompatible(dsn); !errors.Is(err, migrations.ErrSchemaDirty) {
		t.Fatalf("after a failed migration: %v, want %v", err, migrations.ErrSchemaDirty)
	}
	src, err := iofs.New(broken, ".")
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Force(int(latest + 1))
	_, _ = m.Close()
	if err != nil {
		t.Fatalf("put the version back: %v", err)
	}
	carry(t, func(files fstest.MapFS) {
		files[bad] = &fstest.MapFile{Data: []byte(`CREATE TABLE public.runner_repaired (id INT);`)}
	})
	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("the repaired migration: %v", err)
	}
	if st, err := migrations.CheckCompatible(dsn); err != nil || st.Database != latest+2 {
		t.Errorf("after the repair: %+v, %v; want migration %d", st, err, latest+2)
	}
}

// TestTwoStartsAtOnce checks that two instances starting on an empty database
// both come up on one migrated database.
func TestTwoStartsAtOnce(t *testing.T) {
	dsn := emptyDatabase(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() { errs[i] = migrations.Run(dsn) })
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("two starts at once: %v, %v", errs[0], errs[1])
	}
	latest, err := migrations.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if st, err := migrations.CheckCompatible(dsn); err != nil || st.Database != latest {
		t.Errorf("after two starts at once: %+v, %v; want migration %d", st, err, latest)
	}
}
