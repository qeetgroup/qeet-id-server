//go:build integration

package auth

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestSignInsAndRenewalsMakeAPersonMonthlyActive checks that signing in to an
// organisation makes the person active in it this month, once however often
// they sign in, and that renewing the session does too.
func TestSignInsAndRenewalsMakeAPersonMonthlyActive(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, tenant := member(t)
	active := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM tenant.monthly_active_users
			WHERE tenant_id = $1 AND user_id = $2 AND month = date_trunc('month', NOW() AT TIME ZONE 'UTC')::date`, tenant, a.ID)
	}

	pair := signIn(t, svc, a)
	signIn(t, svc, a)
	if n := active(); n != 1 {
		t.Fatalf("after two sign-ins: %d rows, want 1", n)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM tenant.monthly_active_users WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n := active(); n != 1 {
		t.Fatalf("after a renewal: %d rows, want 1", n)
	}
}
