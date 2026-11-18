//go:build integration

package rebac

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestRequestBudgetSpansChecks checks that the checks made with one request's
// budget share it: once together they have read maxRequestExpansions tuple
// sets, the next is refused with ErrReBACCheckTooComplex, while the same check
// in a request of its own is answered.
func TestRequestBudgetSpansChecks(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.relation_tuples (organization_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
		SELECT $1, 'document', 'wide', 'viewer', 'group', 'g' || n, 'member' FROM generate_series(1, $2::int) n`,
		organization, maxExpansions*9/10-1); err != nil {
		t.Fatal(err)
	}
	perCheck := maxExpansions * 9 / 10
	request := WithRequestBudget(ctx)
	for i := 1; ; i++ {
		_, err := svc.Check(request, organization, "document:wide", "viewer", uuid.NewString())
		if i*perCheck <= maxRequestExpansions {
			if err != nil {
				t.Fatalf("check %d within the request's budget: %v", i, err)
			}
			continue
		}
		if !errors.Is(err, ErrCheckTooComplex) {
			t.Errorf("check %d past the request's budget: %v, want %v", i, err, ErrCheckTooComplex)
		}
		break
	}
	if _, err := svc.Check(WithRequestBudget(ctx), organization, "document:wide", "viewer", uuid.NewString()); err != nil {
		t.Errorf("the same check in a request of its own: %v", err)
	}
}
