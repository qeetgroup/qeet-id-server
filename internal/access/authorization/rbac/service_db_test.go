//go:build integration

package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// seatPlan is a plan of n seats.
type seatPlan int

// inviteSeats returns the invitation service as a seat guard of a plan of n
// seats; nothing else of it is used.
func inviteSeats(t *testing.T, pool *pgxpool.Pool, n int) *invite.Service {
	t.Helper()
	seats, err := invite.NewService(pool, invite.Deps{
		Sender: &dbtest.Mailbox{}, Rules: unusedPolicy{}, Methods: unusedPolicy{}, Limits: seatPlan(n),
		Grants: func(context.Context, *httpx.Principal, uuid.UUID, uuid.UUID) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return seats
}

// unusedPolicy stands for the password rules and sign-in methods a seat
// guard never asks.
type unusedPolicy struct {
	authpolicy.PasswordRules
	authpolicy.SignInMethodsChecker
}

// TestRoleGrantsTakeSeats checks that giving someone a first role, directly or
// through a group they are in, takes a seat and is refused once the plan's
// seats are taken, while a second role for someone holding one is not.
func TestRoleGrantsTakeSeats(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newRoleService(t, NewRepository(pool))
	svc.seats = inviteSeats(t, pool, 2)
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

	svc.seats = inviteSeats(t, pool, -1) // a plan without a seat limit
	if err := svc.AssignRoleToGroup(ctx, group, organization, role, &admin.ID, actor); err != nil {
		t.Errorf("a group role on a plan without a seat limit: %v", err)
	}
}

func (n seatPlan) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }
