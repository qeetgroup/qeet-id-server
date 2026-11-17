//go:build integration

package oidc

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestApplicationGrantsMakeAPersonMonthlyActive checks that an application
// redeeming a person's code, and renewing its refresh token, each make the
// person active in the organization this month.
func TestApplicationGrantsMakeAPersonMonthlyActive(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	active := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.monthly_active_users
			WHERE organization_id = $1 AND user_id = $2 AND month = date_trunc('month', NOW() AT TIME ZONE 'UTC')::date`, organization, person.ID)
	}

	first := redeemCode(t, svc, client, secret, person.ID, "")
	if n := active(); n != 1 {
		t.Fatalf("after the code exchange: %d rows, want 1", n)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM organization.monthly_active_users WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, ""); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n := active(); n != 1 {
		t.Fatalf("after the refresh: %d rows, want 1", n)
	}
}
