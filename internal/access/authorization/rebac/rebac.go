// Package rebac is per-organization relationship-based authorization (ReBAC), a
// Zanzibar-style subset. A tuple says a subject (user:<id>, or the userset
// <type>:<id>#<relation>) holds a relation on an object; Check walks tuples and
// expands usersets recursively, with a depth cap and a visited set for cycles.
package rebac

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac/dbgen"
)

// Service manages the relationship tuples.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the relationship service.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }
