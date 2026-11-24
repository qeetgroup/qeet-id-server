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
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
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

// TestOrganizationsKeepAnOwnerButOffboardTheirOwn checks that an organization
// still can't suspend, delete or strip its own last active owner, but can
// suspend and delete its own account when that account is the last owner of an
// organization it created elsewhere.
func TestOrganizationsKeepAnOwnerButOffboardTheirOwn(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Pool(t)
	lastOwner := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "QI409"
	}
	ownerRole := func(organization uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	employer, side := dbtest.Organization(t), dbtest.Organization(t)
	boss := dbtest.User(t, employer)
	dbtest.Assign(t, boss.ID, employer, ownerRole(employer))
	employee := dbtest.User(t, employer, employer)
	sideOwner := ownerRole(side)
	dbtest.Assign(t, employee.ID, side, sideOwner)

	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, boss.ID); !lastOwner(err) {
		t.Errorf("suspend the employer's last owner: %v, want QI409", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, employee.ID, side); !lastOwner(err) {
		t.Errorf("take the owner role from the side organization's last owner: %v, want QI409", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, employee.ID); err != nil {
		t.Errorf("the employer suspends its employee who owns an organization elsewhere: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'active' WHERE id = $1`, employee.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, employee.ID); err != nil {
		t.Errorf("the employer deletes that employee: %v", err)
	}
}

// accountLevelTables are the tables with an organization_id that have no row-level
// security policy: they hold a person's own data across organizations (read by
// "my sessions", "my invitations", sign-in), or are platform-wide.
var accountLevelTables = map[string]bool{
	"audit.events":                  true, // one hash chain per organization and one platform chain
	"platform.organization_purges":  true, // the record of a purged organization, kept after it is gone
	"auth.login_codes":              true, // sign-in, before an organization applies
	"auth.login_context_history":    true, // a person's sign-in history, across organizations
	"auth.magic_links":              true, // sign-in, before an organization applies
	"auth.mfa_login_challenges":     true, // sign-in, before an organization applies
	"auth.mfa_push_pairings":        true, // a person's devices
	"auth.notifications":            true, // a person's inbox, across organizations
	"auth.oauth_states":             true, // sign-in, before an organization applies
	"auth.oidc_authorization_codes": true, // the hosted login, across organizations
	"auth.oidc_ciba_requests":       true, // ended with every sign-in of the person
	"auth.oidc_device_codes":        true, // ended with every sign-in of the person
	"auth.oidc_logout_deliveries":   true, // background delivery
	"auth.oidc_refresh_tokens":      true, // a person's application grants, across organizations
	"auth.sessions":                 true, // a person's sessions, across organizations
	"auth.trusted_devices":          true, // a person's devices, across organizations
	"platform.email_messages":       true, // platform delivery records
	"platform.email_suppressions":   true, // platform suppression list
	"platform.rate_limit_overrides": true, // read by every instance's limiter
	"platform.sales_leads":          true, // the public contact form
	"rbac.user_roles":               true, // a person's memberships, across organizations
	"organization.signup_checkouts": true, // sign-up, before the organization exists
	"account.export_requests":       true, // a person's own data
	"account.external_identities":   true, // a person's linked accounts
	"account.purge_requests":        true, // a person's own data
	"account.users":                 true, // accounts are platform-wide
}

// TestOrganizationTablesHaveRowSecurity checks that every table with an organization_id has
// the organization_isolation policy, unless it is account-level, so a new
// organization-owned table can't be added without one.
func TestOrganizationTablesHaveRowSecurity(t *testing.T) {
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT c.oid::regclass::text, c.relrowsecurity,
		       EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'organization_isolation')
		FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
		WHERE c.relkind = 'r' AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')
		ORDER BY 1
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var table string
		var enabled, policy bool
		if err := rows.Scan(&table, &enabled, &policy); err != nil {
			t.Fatal(err)
		}
		table = unquote(table)
		seen[table] = true
		switch {
		case accountLevelTables[table] && (enabled || policy):
			t.Errorf("%s is listed as account-level but has row-level security", table)
		case !accountLevelTables[table] && (!enabled || !policy):
			t.Errorf("%s has an organization_id but no organization_isolation policy; add one in its migration, or list it in accountLevelTables with why", table)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for table := range accountLevelTables {
		if !seen[table] {
			t.Errorf("%s is listed in accountLevelTables but has no organization_id; delete it from the list", table)
		}
	}
}

// unquote drops the quotes regclass puts around a reserved name ("user").
func unquote(s string) string { return strings.ReplaceAll(s, `"`, "") }

// TestRowSecurityConfinesAScopedConnection checks that a connection scoped to
// one organization sees, writes and changes only that organization's rows,
// whatever its query asks, and that one acting across organizations sees all.
func TestRowSecurityConfinesAScopedConnection(t *testing.T) {
	pool := dbtest.Pool(t)
	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	for _, organization := range []any{mine, theirs} {
		if _, err := pool.Exec(dbtest.Context(t), `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Engineering')`, organization); err != nil {
			t.Fatal(err)
		}
	}
	count := func(ctx context.Context) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM organization.groups WHERE organization_id = ANY($1)`, []any{mine, theirs}).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	scoped := postgres.WithOrganization(dbtest.Context(t), mine)
	if n := count(scoped); n != 1 {
		t.Errorf("scoped to one organization, a query for both sees %d groups, want its own 1", n)
	}
	if n := count(postgres.AcrossOrganizations(scoped)); n != 2 {
		t.Errorf("across organizations, %d groups, want 2", n)
	}
	_, err := pool.Exec(scoped, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Planted')`, theirs)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("scoped, a row for another organization was written: %v, want a row-level security refusal", err)
	}
	tag, err := pool.Exec(scoped, `UPDATE organization.groups SET name = 'Renamed' WHERE organization_id = $1`, theirs)
	if err != nil || tag.RowsAffected() != 0 {
		t.Errorf("scoped, another organization's group was changed: %v rows, %v", tag.RowsAffected(), err)
	}
}

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestReferencesStayInTheirOrganization checks that every foreign key from one
// organization-owned table to another names the organization, so the database
// refuses a row that points at another organization's.
func TestReferencesStayInTheirOrganization(t *testing.T) {
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `
		SELECT c.conrelid::regclass::text, c.conname
		FROM pg_constraint c
		JOIN pg_attribute child ON child.attrelid = c.conrelid AND child.attname = 'organization_id' AND child.attnotnull
		JOIN pg_attribute parent ON parent.attrelid = c.confrelid AND parent.attname = 'organization_id' AND parent.attnotnull
		WHERE c.contype = 'f' AND NOT child.attnum = ANY (c.conkey)
		ORDER BY 1, 2
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, constraint string
		if err := rows.Scan(&table, &constraint); err != nil {
			t.Fatal(err)
		}
		t.Errorf("%s.%s refers to another organization-owned row by id alone; refer to it by (organization_id, id)", table, constraint)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	mine, theirs := dbtest.Organization(t), dbtest.Organization(t)
	user := dbtest.User(t, mine)
	_, err = dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO rbac.user_roles (user_id, organization_id, role_id) VALUES ($1, $2, $3)
	`, user.ID, mine, dbtest.Role(t, theirs))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Errorf("a role from another organization was granted: %v, want a foreign key violation", err)
	}
}
