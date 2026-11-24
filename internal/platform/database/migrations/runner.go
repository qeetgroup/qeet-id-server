// Package migrations embeds the SQL schema migrations and applies them with
// golang-migrate, refusing a database this build can't run on.
package migrations

import (
	"cmp"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
)

//go:embed *.sql
var sqlFiles embed.FS

// source is where the migrations are read from. A test swaps it.
var source fs.FS = sqlFiles

// Run applies every pending up migration to dbURL (a postgres:// URL), returning
// nil when there is none, and records the file that applies each. It changes
// nothing on a database this build can't run on (see CheckCompatible).
// Migrations only ever run up.
func Run(dbURL string) error {
	m, err := open(dbURL)
	if err != nil {
		return err
	}
	defer closeMigrate(m)
	ctx := context.Background()
	conn, err := lockRecords(ctx, dbURL)
	if err != nil {
		return err
	}
	defer closeRecords(conn)
	st, err := status(m)
	if err != nil {
		return err
	}
	if err := checkStatus(st); err != nil {
		return err
	}
	ups, err := upMigrations()
	if err != nil {
		return err
	}
	if err := checkFiles(ctx, conn, st, ups); err != nil {
		return err
	}
	if err := record(ctx, conn, ups, st.Database); err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		if gaveUpWaiting(err) {
			retryNextStart(m, ups)
		}
		return fmt.Errorf("migration up: %w", err)
	}
	return nil
}

// gaveUpWaiting reports whether a migration failed only because it waited
// lockTimeout for a table another connection holds.
func gaveUpWaiting(err error) bool {
	var failed database.Error
	if !errors.As(err, &failed) {
		return false
	}
	var state interface{ SQLState() string }
	return errors.As(failed.OrigErr, &state) && state.SQLState() == "55P03" // lock_not_available
}

// retryNextStart puts the database back to the migration before the one that
// gave up waiting, which changed nothing, so the next start runs it again. A
// migration that isn't one transaction stays half-applied, for a person to
// look at.
func retryNextStart(m *migrate.Migrate, ups []upMigration) {
	version, dirty, err := m.Version()
	if err != nil || !dirty {
		return
	}
	before := -1 // golang-migrate's "nothing applied"
	for _, up := range ups {
		switch {
		case up.version < version:
			before = up.number
		case up.version == version && !up.oneTransaction:
			return
		}
	}
	if err := m.Force(before); err != nil {
		slog.Warn("migrations: put the version back after a busy table", "err", err)
	}
}

// Status is the schema state of a database next to this build.
type Status struct {
	// Database is the migration the database is at (0: none applied); Dirty
	// is set when that migration failed part-way.
	Database uint `json:"database"`
	Dirty    bool `json:"dirty"`
	// Latest is the newest migration this build carries.
	Latest uint `json:"latest"`
}

// Read reports dbURL's schema state without changing anything.
func Read(dbURL string) (Status, error) {
	m, err := open(dbURL)
	if err != nil {
		return Status{}, err
	}
	defer closeMigrate(m)
	return status(m)
}

// ErrSchemaNewer is returned (wrapped in *SchemaError) for a database that a
// later release has migrated past this build's latest migration.
var ErrSchemaNewer = errors.New("database schema is newer than this build")

// ErrSchemaDirty is returned (wrapped in *SchemaError) for a database whose
// last migration failed part-way.
var ErrSchemaDirty = errors.New("database schema is dirty")

// ErrSchemaChanged is returned (wrapped in *SchemaError) for a database whose
// applied migrations aren't recorded as the files this build carries: a file
// was edited, or something that keeps no record migrated the database.
var ErrSchemaChanged = errors.New("database schema isn't recorded as built from this build's migration files")

// SchemaError explains why this build won't run on a database, and what the
// operator does next.
type SchemaError struct {
	Status
	Err error
	// Changed says what differs, for ErrSchemaChanged.
	Changed string
}

// Unwrap returns the underlying error.
func (e *SchemaError) Unwrap() error { return e.Err }

// Error describes the schema state and how to recover.
func (e *SchemaError) Error() string {
	if errors.Is(e.Err, ErrSchemaChanged) {
		return fmt.Sprintf("database schema at migration %d isn't recorded as built from the migration files "+
			"this build carries: %s. This build could run on tables it doesn't expect, so it won't start. On "+
			"a development database, recreate it (make db-reset, or the kit's Reset). Once a release has "+
			"shipped, a migration is never edited after it is applied: restore it and make the change in a "+
			"new migration", e.Database, e.Changed)
	}
	if errors.Is(e.Err, ErrSchemaDirty) {
		return fmt.Sprintf("database schema is dirty at migration %d: that migration failed part-way. "+
			"Nothing will start on it until it is repaired: see the half-applied migration recovery in "+
			"operations/runbooks/database-operations.md (diagnose, force the version, re-run)", e.Database)
	}
	return fmt.Sprintf("database schema is at migration %d, newer than this build knows (its latest is %d): "+
		"a later release migrated it, so this build would run on tables it doesn't expect. It won't start. "+
		"Deploy a release that carries migration %d (roll forward), or restore the database to a point "+
		"before that migration and then deploy this build; migrations are never run down automatically",
		e.Database, e.Latest, e.Database)
}

// CheckCompatible returns dbURL's schema state, and a *SchemaError if the
// database is dirty, newer than this build or built from other migration
// files, without changing anything.
func CheckCompatible(dbURL string) (Status, error) {
	m, err := open(dbURL)
	if err != nil {
		return Status{}, err
	}
	defer closeMigrate(m)
	st, err := status(m)
	if err != nil {
		return st, err
	}
	if err := checkStatus(st); err != nil || st.Database == 0 {
		return st, err
	}
	ups, err := upMigrations()
	if err != nil {
		return st, err
	}
	ctx := context.Background()
	conn, err := connect(ctx, dbURL)
	if err != nil {
		return st, err
	}
	defer closeRecords(conn)
	return st, checkFiles(ctx, conn, st, ups)
}

// Fingerprint identifies the migrations this build carries by their names and
// contents, so a database built from them can be told from one built before a
// migration was edited.
func Fingerprint() (string, error) {
	h := sha256.New()
	err := fs.WalkDir(source, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(source, path)
		if err != nil {
			return err
		}
		h.Write(fmt.Appendf(nil, "%s\x00%d\x00", path, len(raw)))
		h.Write(raw)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// Latest returns the newest migration this build carries.
func Latest() (uint, error) {
	ups, err := upMigrations()
	if err != nil {
		return 0, err
	}
	return ups[len(ups)-1].version, nil
}

// upMigration is one up migration this build carries.
type upMigration struct {
	version  uint
	number   int    // version, as golang-migrate's Force takes it
	name     string // its file
	checksum string // the SHA-256 of the file's contents, in hex
	// oneTransaction is set when PostgreSQL runs the file as one transaction,
	// so a failure leaves nothing behind.
	oneTransaction bool
}

// ownTransactions matches what stops a file running as one transaction: a
// concurrent index build, or transaction control of its own.
var ownTransactions = regexp.MustCompile(`(?i)\b(CONCURRENTLY|COMMIT)\b`)

// upMigrations returns the up migrations this build carries, oldest first.
func upMigrations() ([]upMigration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, err
	}
	var ups []upMigration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		v, err := strconv.ParseUint(num, 10, 31)
		number, _ := strconv.Atoi(num)
		if err != nil || v == 0 {
			continue
		}
		raw, err := fs.ReadFile(source, e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		ups = append(ups, upMigration{
			version: uint(v), number: number, name: e.Name(), checksum: hex.EncodeToString(sum[:]),
			oneTransaction: !ownTransactions.Match(raw),
		})
	}
	if len(ups) == 0 {
		return nil, errors.New("migrations: none embedded")
	}
	slices.SortFunc(ups, func(a, b upMigration) int { return cmp.Compare(a.version, b.version) })
	return ups, nil
}

// recordsLock is the advisory lock a runner holds from reading what a database
// has applied until it has migrated it, so two builds starting at once can't
// record one file and apply another.
const recordsLock = int64(0x5145455449444D49)

// lockRecords connects to dbURL and takes recordsLock, released when the
// connection closes.
func lockRecords(ctx context.Context, dbURL string) (*pgx.Conn, error) {
	conn, err := connect(ctx, dbURL)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, recordsLock); err != nil {
		closeRecords(conn)
		return nil, fmt.Errorf("migration records: wait for another instance to finish migrating: %w", err)
	}
	return conn, nil
}

// connect opens the runner's own connection to dbURL, with the lock timeout
// the migrations have.
func connect(ctx context.Context, dbURL string) (*pgx.Conn, error) {
	u, err := withLockTimeout(dbURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for name := range q {
		if strings.HasPrefix(name, "x-") { // golang-migrate's own options
			q.Del(name)
		}
	}
	u.RawQuery = q.Encode()
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("migration records: connect: %w", err)
	}
	return conn, nil
}

func closeRecords(conn *pgx.Conn) {
	if err := conn.Close(context.Background()); err != nil {
		slog.Warn("migrations: close", "db_err", err)
	}
}

// checkFiles returns a *SchemaError if the files recorded for the migrations
// the database has applied aren't the ones this build carries.
func checkFiles(ctx context.Context, conn *pgx.Conn, st Status, ups []upMigration) error {
	recorded := map[uint]string{}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.schema_migration_checksums') IS NOT NULL`).Scan(&exists); err != nil {
		return fmt.Errorf("migration records: %w", err)
	}
	if exists {
		rows, err := conn.Query(ctx, `SELECT version, checksum FROM public.schema_migration_checksums WHERE version <= $1`, st.Database)
		if err != nil {
			return fmt.Errorf("migration records: %w", err)
		}
		var version uint
		var checksum string
		if _, err := pgx.ForEachRow(rows, []any{&version, &checksum}, func() error {
			recorded[version] = checksum
			return nil
		}); err != nil {
			return fmt.Errorf("migration records: %w", err)
		}
	}
	if what := changed(ups, recorded, st.Database); what != "" {
		return &SchemaError{Status: st, Err: ErrSchemaChanged, Changed: what}
	}
	return nil
}

// changed says how the files recorded for the migrations applied up to through
// differ from ups, the ones this build carries, or "" when they are the same.
func changed(ups []upMigration, recorded map[uint]string, through uint) string {
	carried := map[uint]bool{}
	for _, up := range ups {
		if up.version > through {
			break
		}
		carried[up.version] = true
		switch was, ok := recorded[up.version]; {
		case !ok:
			return fmt.Sprintf("it has no record of the file that applied %s (a build from before the records, or the migrate tool, migrated it)", up.name)
		case was != up.checksum:
			return fmt.Sprintf("%s differs from the file that was applied", up.name)
		}
	}
	for version := uint(1); version <= through; version++ {
		if _, ok := recorded[version]; ok && !carried[version] {
			return fmt.Sprintf("migration %d was applied and this build doesn't carry it", version)
		}
	}
	if through > 0 && !carried[through] {
		return fmt.Sprintf("it is at migration %d and this build doesn't carry it", through)
	}
	return ""
}

// record stores the checksum of each of ups after applied, the migrations
// about to run, replacing what an attempt that was rolled back left. It makes
// the table on a database's first migration.
func record(ctx context.Context, conn *pgx.Conn, ups []upMigration, applied uint) error {
	batch := &pgx.Batch{}
	for _, up := range ups {
		if up.version > applied {
			batch.Queue(`INSERT INTO public.schema_migration_checksums (version, checksum) VALUES ($1, $2)
				ON CONFLICT (version) DO UPDATE SET checksum = EXCLUDED.checksum`, up.version, up.checksum)
		}
	}
	if batch.Len() == 0 {
		return nil
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.schema_migration_checksums (
		version  BIGINT PRIMARY KEY,
		checksum TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("migration records: %w", err)
	}
	// A record above the database's migration is of one that was rolled back.
	if _, err := conn.Exec(ctx, `DELETE FROM public.schema_migration_checksums WHERE version > $1`, applied); err != nil {
		return fmt.Errorf("migration records: %w", err)
	}
	if err := conn.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("migration records: %w", err)
	}
	return nil
}

// lockTimeout bounds how long a migration waits for a table another
// connection holds. Waiting longer would queue every query to that table
// behind the migration and stall the application, so the migration fails
// instead and runs again at the next start (retryNextStart). A test shortens it.
var lockTimeout = "10s"

func open(dbURL string) (*migrate.Migrate, error) {
	d, err := iofs.New(source, ".")
	if err != nil {
		return nil, fmt.Errorf("migration source: %w", err)
	}
	u, err := withLockTimeout(dbURL)
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, u.String())
	if err != nil {
		return nil, fmt.Errorf("migration init: %w", err)
	}
	return m, nil
}

// withLockTimeout is dbURL with lockTimeout, unless it sets its own.
func withLockTimeout(dbURL string) (*url.URL, error) {
	u, err := url.Parse(dbURL)
	if err != nil {
		return nil, fmt.Errorf("migration database url: %w", err)
	}
	q := u.Query()
	if q.Get("lock_timeout") == "" {
		q.Set("lock_timeout", lockTimeout) // a server setting, passed at connection start
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func status(m *migrate.Migrate) (Status, error) {
	latest, err := Latest()
	if err != nil {
		return Status{}, err
	}
	v, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return Status{Latest: latest}, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("migration version: %w", err)
	}
	return Status{Database: v, Dirty: dirty, Latest: latest}, nil
}

func checkStatus(st Status) error {
	switch {
	case st.Dirty:
		return &SchemaError{Status: st, Err: ErrSchemaDirty}
	case st.Database > st.Latest:
		return &SchemaError{Status: st, Err: ErrSchemaNewer}
	}
	return nil
}

// closeMigrate releases the migration source and database connections; a
// failure to close leaves nothing to undo, so it is only logged.
func closeMigrate(m *migrate.Migrate) {
	if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
		slog.Warn("migrations: close", "source_err", srcErr, "db_err", dbErr)
	}
}
