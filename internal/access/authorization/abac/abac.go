// Package abac stores per-organization attribute-based access control policies and
// evaluates them deny-wins: among enabled policies for the resource type and
// action (exact or "*"), a matching deny refuses, else a matching allow
// permits, else the answer is deny. Conditions are JSON trees (EvaluateCondition).
package abac

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
)

// Service stores each organization's ABAC policies and evaluates requests against
// them.
type Service struct {
	pool      *pgxpool.Pool
	q         *dbgen.Queries
	gate      entitlements.PlanGate
	relations RelationCheck

	presenceMu sync.Mutex
	presence   map[uuid.UUID]presenceEntry
}

// NewService returns the ABAC policy service. gate decides whether an
// organization's plan includes ABAC; relations answers relation conditions.
func NewService(pool *pgxpool.Pool, gate entitlements.PlanGate, relations RelationCheck) (*Service, error) {
	switch {
	case gate == nil:
		return nil, errors.New("abac: the policy service needs a plan gate")
	case relations == nil:
		return nil, errors.New("abac: the policy service needs a relation check")
	}
	return &Service{pool: pool, q: dbgen.New(pool), gate: gate, relations: relations, presence: map[uuid.UUID]presenceEntry{}}, nil
}
