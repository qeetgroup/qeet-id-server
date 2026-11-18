//go:build integration

package rebac

import (
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestExpandStopsAtItsBudget checks that the graph of a relationship set wider
// than a request's budget is refused with ErrReBACCheckTooComplex rather than
// read one tuple set at a time without end, while a narrower one is drawn.
func TestExpandStopsAtItsBudget(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	for object, groups := range map[string]int{"wide": maxRequestExpansions + 1, "narrow": 10} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO auth.relation_tuples (organization_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
			SELECT $1, 'document', $2, 'viewer', 'group', $2 || n, 'member' FROM generate_series(1, $3::int) n`,
			organization, object, groups); err != nil {
			t.Fatal(err)
		}
	}
	if g, err := svc.Expand(ctx, organization, "document:wide", "viewer", maxExpandDepth); !errors.Is(err, ErrCheckTooComplex) {
		t.Errorf("the graph of %d groups: %v, %v; want %v", maxRequestExpansions+1, g != nil, err, ErrCheckTooComplex)
	}
	if g, err := svc.Expand(ctx, organization, "document:narrow", "viewer", maxExpandDepth); err != nil || len(g.Nodes) != 11 {
		t.Errorf("the graph of 10 groups: %v, want its 11 nodes", err)
	}
}
