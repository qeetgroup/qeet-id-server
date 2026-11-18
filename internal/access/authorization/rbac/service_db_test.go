//go:build integration

package rbac

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// seatPlan is a plan of n seats.
type seatPlan int

// TestRoleGrantsTakeSeats checks that giving someone a first role, directly or
// through a group they are in, takes a seat and is refused once the plan's
// seats are taken, while a second role for someone holding one is not.
func TestRoleGrantsTakeSeats(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	seats := invite.NewService(pool, &dbtest.Mailbox{}, time.Hour, "https://app.example.test")
	seats.SetPlanLimiter(seatPlan(2))
	svc := NewService(NewRepository(pool))
	svc.SetSeatGuard(seats)
	organization := dbtest.Organization(t)
	role := dbtest.Role(t, organization)
	admin := dbtest.User(t, organization, organization)
	first, second, third := dbtest.User(t, organization), dbtest.User(t, organization), dbtest.User(t, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}

	if err := svc.AssignRole(ctx, first.ID, organization, role, &admin.ID, actor); err != nil {
		t.Fatalf("a first role for the last seat: %v", err)
	}
	if err := svc.AssignRole(ctx, second.ID, organization, role, &admin.ID, actor); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("a first role with no seat left: %v, want %v", err, errs.ErrPlanLimit)
	}
	if err := svc.AssignRole(ctx, first.ID, organization, dbtest.Role(t, organization), &admin.ID, actor); err != nil {
		t.Errorf("a second role for someone holding one: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, second.ID, organization); n != 0 {
		t.Errorf("the refused role was granted")
	}

	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Support') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	for _, member := range []uuid.UUID{first.ID, third.ID} {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, group, member, organization); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.AssignRoleToGroup(ctx, group, organization, role, &admin.ID, actor); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("a role for a group with a member holding none and no seat left: %v, want %v", err, errs.ErrPlanLimit)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.group_roles WHERE group_id = $1`, group); n != 0 {
		t.Errorf("the refused group role was granted")
	}

	seats.SetPlanLimiter(seatPlan(-1)) // a plan without a seat limit
	if err := svc.AssignRoleToGroup(ctx, group, organization, role, &admin.ID, actor); err != nil {
		t.Errorf("a group role on a plan without a seat limit: %v", err)
	}
}

func (n seatPlan) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }
