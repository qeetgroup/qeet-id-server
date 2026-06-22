package pgxerr_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/pgxerr"
)

func TestPredicates(t *testing.T) {
	uniq := &pgconn.PgError{Code: "23505"}
	fk := &pgconn.PgError{Code: "23503"}
	other := errors.New("boom")

	if !pgxerr.IsUnique(uniq) || pgxerr.IsUnique(fk) || pgxerr.IsUnique(other) {
		t.Error("IsUnique mismatch")
	}
	if !pgxerr.IsForeignKey(fk) || pgxerr.IsForeignKey(uniq) || pgxerr.IsForeignKey(other) {
		t.Error("IsForeignKey mismatch")
	}
	// Predicates must see through wrapping.
	if !pgxerr.IsUnique(fmt.Errorf("insert: %w", uniq)) {
		t.Error("IsUnique should unwrap")
	}
}

func TestTranslate(t *testing.T) {
	if got := pgxerr.Translate(&pgconn.PgError{Code: "23505"}); got != errs.ErrConflict {
		t.Errorf("23505 -> %v, want ErrConflict", got)
	}
	other := errors.New("boom")
	if got := pgxerr.Translate(other); got != other {
		t.Errorf("non-pg error should pass through, got %v", got)
	}
	if got := pgxerr.Translate(nil); got != nil {
		t.Errorf("nil should pass through, got %v", got)
	}
}
