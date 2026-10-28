//go:build integration

package group

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// seatPlan is a plan of n seats.
type seatPlan int

func (n seatPlan) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }

// TestJoiningAGroupWithARoleTakesASeat checks that joining a group that
// carries a role gives someone holding none a seat, refused once the plan's
// seats are taken, while joining a group without one takes no seat.
func TestJoiningAGroupWithARoleTakesASeat(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	seats := invite.NewService(pool, &dbtest.Mailbox{}, time.Hour, "https://app.example.test")
	seats.SetPlanLimiter(seatPlan(1))
	svc := NewService(pool)
	svc.SetSeatGuard(seats)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant) // the one seat
	customer := dbtest.User(t, tenant)
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}
	group := func(name string, roles ...uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, tenant, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, role := range roles {
			if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, tenant, id, role); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}

	if err := svc.AddMember(ctx, group("Newsletter"), customer.ID, tenant, actor); err != nil {
		t.Errorf("joining a group without a role, with no seat left: %v", err)
	}
	support := group("Support", dbtest.Role(t, tenant))
	if err := svc.AddMember(ctx, support, customer.ID, tenant, actor); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("joining a group with a role, with no seat left: %v, want %v", err, errs.ErrPlanLimit)
	}
	if err := svc.AddMember(ctx, support, admin.ID, tenant, actor); err != nil {
		t.Errorf("someone holding a role joins a group with one: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.group_members WHERE group_id = $1 AND user_id = $2`, support, customer.ID); n != 0 {
		t.Errorf("the refused member was added")
	}
}
