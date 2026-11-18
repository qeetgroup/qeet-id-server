package postgres_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

func TestPredicates(t *testing.T) {
	uniq := &pgconn.PgError{Code: "23505"}
	fk := &pgconn.PgError{Code: "23503"}
	other := errors.New("boom")

	if !postgres.IsUnique(uniq) || postgres.IsUnique(fk) || postgres.IsUnique(other) {
		t.Error("IsUnique mismatch")
	}
	if !postgres.IsForeignKey(fk) || postgres.IsForeignKey(uniq) || postgres.IsForeignKey(other) {
		t.Error("IsForeignKey mismatch")
	}
	// Predicates must see through wrapping.
	if !postgres.IsUnique(fmt.Errorf("insert: %w", uniq)) {
		t.Error("IsUnique should unwrap")
	}
}
