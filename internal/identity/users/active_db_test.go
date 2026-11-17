//go:build integration

package user

import (
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestMonthlyActiveUsersCountEachPersonOnce checks that a person active in an
// organization several times this month counts once, that another person
// counts, that another organization's people and earlier months don't, and
// that an organization-less session records nothing.
func TestMonthlyActiveUsersCountEachPersonOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	a, b := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, other, other)
	repo := NewRepository(pool)

	for range 3 {
		if err := RecordActive(ctx, pool, organization, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordActive(ctx, pool, organization, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := RecordActive(ctx, pool, other, outsider.ID); err != nil {
		t.Fatal(err)
	}
	if err := RecordActive(ctx, pool, uuid.Nil, a.ID); err != nil {
		t.Fatal(err)
	}
	// Last month's activity belongs to last month.
	if _, err := pool.Exec(ctx, `INSERT INTO organization.monthly_active_users (organization_id, month, user_id)
		VALUES ($1, (date_trunc('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '1 month')::date, $2)`, organization, uuid.New()); err != nil {
		t.Fatal(err)
	}

	if n, err := repo.CountMonthlyActive(ctx, organization); err != nil || n != 2 {
		t.Fatalf("this month: %d, %v; want 2", n, err)
	}
	if n, err := repo.CountMonthlyActive(ctx, other); err != nil || n != 1 {
		t.Fatalf("the other organisation: %d, %v; want 1", n, err)
	}
}
