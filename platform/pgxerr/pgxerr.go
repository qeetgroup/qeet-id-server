// Package pgxerr translates PostgreSQL driver errors into domain errs values
// so repositories don't each hand-roll pgconn error-code checks.
package pgxerr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id/platform/errs"
)

// IsUnique reports whether err is a Postgres unique_violation (23505).
func IsUnique(err error) bool { return code(err) == "23505" }

// IsForeignKey reports whether err is a Postgres foreign_key_violation (23503).
func IsForeignKey(err error) bool { return code(err) == "23503" }

// Translate maps a Postgres driver error to a domain errs value, passing
// non-pg errors through unchanged. Use IsUnique/IsForeignKey instead when you
// need a resource-specific message.
func Translate(err error) error {
	switch code(err) {
	case "23505":
		return errs.ErrConflict
	case "23503":
		return errs.ErrBadRequest.WithDetail("references a resource that does not exist")
	case "23502":
		return errs.ErrUnprocessable.WithDetail("missing required field")
	case "23514":
		return errs.ErrUnprocessable.WithDetail("value violates a constraint")
	default:
		return err
	}
}

func code(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}
