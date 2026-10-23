// Package pgxerr translates PostgreSQL driver errors into domain errs values
// so repositories don't each hand-roll pgconn error-code checks.
package pgxerr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsUnique reports whether err is a Postgres unique_violation (23505).
func IsUnique(err error) bool { return code(err) == "23505" }

// IsForeignKey reports whether err is a Postgres foreign_key_violation (23503).
func IsForeignKey(err error) bool { return code(err) == "23503" }

// IsLastOwner reports whether err is the database refusing to take away an
// organisation's last active owner (SQLSTATE QI409, migration 0151).
func IsLastOwner(err error) bool { return code(err) == "QI409" }

func code(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
