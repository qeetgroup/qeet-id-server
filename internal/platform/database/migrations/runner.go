// Package migrations embeds the SQL schema migrations and applies them with
// golang-migrate, refusing a database this build can't run on.
package migrations

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed *.sql
var sqlFiles embed.FS

// Run applies every pending up migration to dbURL (a postgres:// URL), returning
// nil when there is none. It changes nothing on a database this build can't run
// on (see CheckCompatible), such as one a later release migrated further.
// Migrations only ever run up.
func Run(dbURL string) error {
	m, err := open(dbURL)
	if err != nil {
		return err
	}
	defer closeMigrate(m)
	if err := compatible(m); err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migration up: %w", err)
	}
	return nil
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

// SchemaError explains why this build won't run on a database, and what the
// operator does next.
type SchemaError struct {
	Status
	Err error
}

func (e *SchemaError) Unwrap() error { return e.Err }

func (e *SchemaError) Error() string {
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
// database is dirty or newer than this build, without changing anything.
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
	return st, checkStatus(st)
}

// Latest returns the newest migration this build carries.
func Latest() (uint, error) {
	entries, err := fs.ReadDir(sqlFiles, ".")
	if err != nil {
		return 0, err
	}
	var latest uint
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		v, err := strconv.ParseUint(num, 10, 32)
		if err != nil {
			continue
		}
		if uint(v) > latest {
			latest = uint(v)
		}
	}
	if latest == 0 {
		return 0, errors.New("migrations: none embedded")
	}
	return latest, nil
}

func open(dbURL string) (*migrate.Migrate, error) {
	d, err := iofs.New(sqlFiles, ".")
	if err != nil {
		return nil, fmt.Errorf("migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, dbURL)
	if err != nil {
		return nil, fmt.Errorf("migration init: %w", err)
	}
	return m, nil
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

func compatible(m *migrate.Migrate) error {
	st, err := status(m)
	if err != nil {
		return err
	}
	return checkStatus(st)
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
