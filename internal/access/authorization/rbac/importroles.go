package rbac

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// ImportRoles lets a bulk user import give a role, with the checks assigning
// one to a person makes: the caller holds role.write and the role's authority,
// and a person's first role takes one of the plan's seats.
type ImportRoles struct {
	Repo  *Repository
	Seats entitlements.SeatGuard
}

// CheckGrant refuses r's caller giving roleID of organizationID to anyone, and
// returns the organization's seat cap for Assign.
func (g ImportRoles) CheckGrant(r *http.Request, organizationID, roleID uuid.UUID) (int, error) {
	caller := httpx.PrincipalFromCtx(r.Context())
	ok, err := Holds(r.Context(), g.Repo, caller, "role.write")
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errs.ErrRBACPermissionDenied.WithDetail("giving a role needs role.write")
	}
	if err := g.Repo.CheckGrantRole(r.Context(), caller, organizationID, roleID); err != nil {
		return 0, err
	}
	return g.Seats.SeatLimit(r.Context(), organizationID)
}

// Assign gives roleID to userID in organizationID on tx, refusing it when it
// takes a seat beyond seats.
func (g ImportRoles) Assign(ctx context.Context, tx pgx.Tx, userID, organizationID, roleID uuid.UUID, grantedBy *uuid.UUID, seats int) error {
	return g.Seats.WithinSeats(ctx, tx, organizationID, seats, func() error {
		return g.Repo.AssignRole(ctx, tx, userID, organizationID, roleID, grantedBy)
	})
}
