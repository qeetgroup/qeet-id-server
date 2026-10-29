//go:build integration

package bootstrap

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// seatCap is a plan that caps seats at its value.
type seatCap int

func (c seatCap) Limit(context.Context, uuid.UUID, string) (int, error) { return int(c), nil }

// TestBulkImportRolesTakeSeats checks that a bulk import giving everyone a
// role counts each person against the plan's seats: rows past the cap are
// refused with billing.plan_limit and get no account, the rest go in.
func TestBulkImportRolesTakeSeats(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	dbtest.Assign(t, admin.ID, tenant, dbtest.Role(t, tenant, "role.write"))
	var member uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'Member') RETURNING id`, tenant).Scan(&member); err != nil {
		t.Fatal(err)
	}
	seats := invite.NewService(pool, nil, 14*24*time.Hour, "https://app.example.test")
	seats.SetPlanLimiter(seatCap(3))
	h := &user.Handler{Repo: user.NewRepository(pool), Validate: newValidator(), Roles: importRoles{repo: rbac.NewRepository(pool), seats: seats}}
	rows := []map[string]any{}
	for range 3 {
		rows = append(rows, map[string]any{"email": dbtest.Unique("member") + "@example.test"})
	}

	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount), http.MethodPost, "/users/bulk", map[string]any{"users": rows, "role_id": member})
	var res user.BulkImportResult
	dbtest.Decode(t, rec, &res)
	if rec.Code != http.StatusOK || res.Succeeded != 2 || res.Failed != 1 || len(res.Errors) != 1 || res.Errors[0].Code != errs.CodePlanLimit {
		t.Fatalf("import of 3 with 2 seats free: %d %+v; want 2 in and the third refused with %s", rec.Code, res, errs.CodePlanLimit)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, res.Errors[0].Email); n != 0 {
		t.Errorf("the refused row got %d accounts, want none", n)
	}
}
