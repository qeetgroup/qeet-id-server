package pgxerr_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
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
