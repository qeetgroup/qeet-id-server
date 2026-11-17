//go:build integration

package scim

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// seatPlan is a plan of n seats.
type seatPlan int

func (n seatPlan) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }

// TestDirectoryGroupMembershipTakesSeats checks that a directory adding someone
// holding no role to a group that carries one takes a seat, refused in the
// SCIM error format once the plan's seats are taken, by a PATCH and a PUT
// alike, and that the refused member isn't added.
func TestDirectoryGroupMembershipTakesSeats(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSCIMFixture(t, ctx)
	seats := invite.NewService(pool, &dbtest.Mailbox{}, time.Hour, "https://app.example.test")
	seats.SetPlanLimiter(seatPlan(1))
	f.svc.SetSeatGuard(seats)
	dbtest.User(t, f.organizationID, f.organizationID) // holds the one seat
	member := f.seedUser(t, ctx, dbtest.Unique("member")+"@acme.test")

	rec := f.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{"schemas": []string{schemaGroup}, "displayName": "Support"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	gid, _ := decodeBody(t, rec)["id"].(string)
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`,
		f.organizationID, gid, dbtest.Role(t, f.organizationID)); err != nil {
		t.Fatal(err)
	}

	for name, req := range map[string]struct {
		method string
		body   map[string]any
	}{
		"PATCH add": {http.MethodPatch, map[string]any{
			"schemas":    []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": member.String()}}}},
		}},
		"PUT": {http.MethodPut, map[string]any{
			"schemas": []string{schemaGroup}, "displayName": "Support", "members": []map[string]any{{"value": member.String()}},
		}},
	} {
		rec := f.do(t, req.method, "/scim/v2/Groups/"+gid, req.body)
		body := decodeBody(t, rec)
		if rec.Code != http.StatusForbidden || body["schemas"] == nil || body["status"] != "403" {
			t.Errorf("%s with no seat left: status %d %s, want a SCIM 403", name, rec.Code, rec.Body.String())
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE group_id = $1`, gid); n != 0 {
		t.Errorf("%d members added past the seat limit, want none", n)
	}

	seats.SetPlanLimiter(seatPlan(-1)) // a plan without a seat limit
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": member.String()}}}},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("PATCH add on a plan without a seat limit: status %d %s", rec.Code, rec.Body.String())
	}
}
