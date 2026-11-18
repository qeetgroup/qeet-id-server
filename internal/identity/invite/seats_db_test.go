//go:build integration

package invite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// seatPlan is a plan of n seats.
type seatPlan int

func (n seatPlan) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }

// withinSeats runs change through svc.WithinSeats in a transaction it commits
// only on success.
func withinSeats(t *testing.T, svc *Service, organization uuid.UUID, change func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := dbtest.Context(t)
	limit, err := svc.SeatLimit(ctx, organization)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := svc.WithinSeats(ctx, tx, organization, limit, func() error { return change(tx) }); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// grant gives userID roleID in organization.
func grant(userID, organization, roleID uuid.UUID) func(pgx.Tx) error {
	return func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO rbac.user_roles (user_id, organization_id, role_id) VALUES ($1, $2, $3)`, userID, organization, roleID)
		return err
	}
}

// TestSeatsAreThePeopleHoldingARole checks that a seat is a person holding a
// role, directly or through a group, or a pending invitation; that an account
// without a role holds none; that a person's second role takes no other seat;
// and that a first role beyond the plan's seats is refused.
func TestSeatsAreThePeopleHoldingARole(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, &dbtest.Mailbox{}, time.Hour, "https://app.example.test")
	svc.SetPlanLimiter(seatPlan(3))
	organization := dbtest.Organization(t)
	role := dbtest.Role(t, organization)
	owner := dbtest.User(t, organization, organization)
	customers := []dbtest.Account{dbtest.User(t, organization), dbtest.User(t, organization), dbtest.User(t, organization)}
	seats := func() int {
		t.Helper()
		n, err := svc.CountSeats(ctx, organization)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := seats(); n != 1 {
		t.Fatalf("seats with an owner and three customers = %d, want 1", n)
	}

	if err := withinSeats(t, svc, organization, grant(customers[0].ID, organization, role)); err != nil {
		t.Fatalf("a first role within the seats: %v", err)
	}
	if _, _, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("invitee") + "@example.test", RoleID: &role}, audit.Actor{}); err != nil {
		t.Fatalf("an invitation for the last seat: %v", err)
	}
	if n := seats(); n != 3 {
		t.Fatalf("seats = %d, want 3: two people holding a role and an invitation", n)
	}

	if err := withinSeats(t, svc, organization, grant(owner.ID, organization, dbtest.Role(t, organization))); err != nil {
		t.Errorf("a second role for someone holding one, with no seat left: %v", err)
	}
	if err := withinSeats(t, svc, organization, grant(customers[1].ID, organization, role)); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("a first role with no seat left: %v, want %v", err, errs.ErrPlanLimit)
	}
	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Admins') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, group, role); err != nil {
		t.Fatal(err)
	}
	joinGroup := func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, group, customers[2].ID, organization)
		return err
	}
	if err := withinSeats(t, svc, organization, joinGroup); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("a role through a group with no seat left: %v, want %v", err, errs.ErrPlanLimit)
	}
	if _, _, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Email: dbtest.Unique("invitee") + "@example.test", RoleID: &role}, audit.Actor{}); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("an invitation with no seat left: %v, want %v", err, errs.ErrPlanLimit)
	}
	if n := seats(); n != 3 {
		t.Errorf("seats after the refusals = %d, want 3", n)
	}

	svc.SetPlanLimiter(seatPlan(-1)) // a plan without a seat limit
	if err := withinSeats(t, svc, organization, joinGroup); err != nil {
		t.Errorf("a role through a group on a plan without a seat limit: %v", err)
	}
	if n := seats(); n != 4 {
		t.Errorf("seats with a group member holding its role = %d, want 4", n)
	}
}
