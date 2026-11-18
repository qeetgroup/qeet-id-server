//go:build integration

package rbac

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestBulkImportRolesTakeSeats checks that a bulk import giving everyone a
// role counts each person against the plan's seats: rows past the cap are
// refused with billing.plan_limit and get no account, the rest go in.
func TestBulkImportRolesTakeSeats(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "role.write"))
	var member uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name) VALUES ($1, 'Member') RETURNING id`, organization).Scan(&member); err != nil {
		t.Fatal(err)
	}
	seats := invite.NewService(pool, nil, 14*24*time.Hour, "https://app.example.test")
	seats.SetPlanLimiter(seatPlan(3))
	h := &user.Handler{Repo: user.NewRepository(pool), Validate: validator.New(validator.WithRequiredStructEnabled()),
		Roles: ImportRoles{Repo: NewRepository(pool), Seats: seats}}
	rows := []map[string]any{}
	for range 3 {
		rows = append(rows, map[string]any{"email": dbtest.Unique("member") + "@example.test"})
	}

	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount), http.MethodPost, "/users/bulk", map[string]any{"users": rows, "role_id": member})
	var res user.BulkImportResult
	dbtest.Decode(t, rec, &res)
	if rec.Code != http.StatusOK || res.Succeeded != 2 || res.Failed != 1 || len(res.Errors) != 1 || res.Errors[0].Code != errs.CodePlanLimit {
		t.Fatalf("import of 3 with 2 seats free: %d %+v; want 2 in and the third refused with %s", rec.Code, res, errs.CodePlanLimit)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, res.Errors[0].Email); n != 0 {
		t.Errorf("the refused row got %d accounts, want none", n)
	}
}

// TestImportRolesNeedRoleWrite checks that giving a role in an import needs
// role.write, refused with rbac.permission_denied without it, and with it
// answers the organization's seat cap.
func TestImportRolesNeedRoleWrite(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	writer, reader := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	dbtest.Assign(t, writer.ID, organization, dbtest.Role(t, organization, "role.write"))
	dbtest.Assign(t, reader.ID, organization, dbtest.Role(t, organization, "user.write"))
	role := dbtest.Role(t, organization)
	seats := invite.NewService(pool, nil, 14*24*time.Hour, "https://app.example.test")
	seats.SetPlanLimiter(seatPlan(3))
	grants := ImportRoles{Repo: NewRepository(pool), Seats: seats}
	as := func(userID uuid.UUID) *http.Request {
		r := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, "/v1/users/bulk", nil)
		return r.WithContext(httpx.WithPrincipal(r.Context(), dbtest.Principal(userID, organization)))
	}
	if _, err := grants.CheckGrant(as(reader.ID), organization, role); !errors.Is(err, errs.ErrRBACPermissionDenied) {
		t.Errorf("without role.write: %v, want %v", err, errs.ErrRBACPermissionDenied)
	}
	if n, err := grants.CheckGrant(as(writer.ID), organization, role); err != nil || n != 3 {
		t.Errorf("with role.write: seats %d, %v; want the plan's 3", n, err)
	}
}
