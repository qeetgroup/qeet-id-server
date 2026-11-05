package bootstrap

import (
	"context"
	"net/http"
	"time"

	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// billingOrgProvisioner adapts the tenant repository to billing.OrgProvisioner,
// so billing can create an organization after a paid checkout.
type billingOrgProvisioner struct{ tenants *tenant.Repository }

func (p billingOrgProvisioner) ProvisionOrg(ctx context.Context, ownerID uuid.UUID, name, slug, region, plan string) (uuid.UUID, error) {
	t, err := p.tenants.CreateWithOwner(ctx, tenant.CreateInput{Slug: slug, Name: name, Plan: plan, Region: region}, ownerID)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// entitlementPlanResolver returns a tenant's effective plan: the billing
// subscription first, then the tenant's plan label, otherwise free.
type entitlementPlanResolver struct {
	billing *billing.Service
	tenants *tenant.Repository
}

func (r entitlementPlanResolver) EffectivePlan(ctx context.Context, tenantID uuid.UUID) (string, error) {
	if r.billing != nil {
		if sub, err := r.billing.GetSubscription(ctx, tenantID); err == nil && sub != nil && sub.PlanCode != "" {
			// A subscription past its paid period or trial, or canceled, grants
			// nothing: the tenant is on free, not on the stale label. Evaluated
			// lazily here, with no scheduler.
			if sub.Grants(time.Now()) {
				return sub.PlanCode, nil
			}
			return "free", nil
		}
	}
	if r.tenants != nil {
		if t, err := r.tenants.Get(ctx, tenantID); err == nil && t != nil {
			return t.Plan, nil
		}
	}
	return "free", nil
}

// entitlementUsageResolver reports a tenant's current consumption for the
// billing usage-vs-limits display. It reuses the same count queries the plan
// gates check against. Best-effort per resource: a failed count is omitted
// rather than failing the whole response.
type entitlementUsageResolver struct {
	invites  *invite.Service
	oidc     *oidc.Service
	apikeys  *apikey.Service
	rbacRepo *rbac.Repository
	users    *user.Repository
}

func (u entitlementUsageResolver) Usage(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	out := map[string]int{}
	if u.invites != nil {
		if n, err := u.invites.CountSeats(ctx, tenantID); err == nil {
			out["seats"] = n
		}
	}
	if u.oidc != nil {
		if n, err := u.oidc.CountClients(ctx, tenantID); err == nil {
			out["apps"] = n
		}
	}
	if u.apikeys != nil {
		if n, err := u.apikeys.CountActive(ctx, tenantID); err == nil {
			out["api_keys"] = n
		}
	}
	if u.rbacRepo != nil {
		if n, err := u.rbacRepo.CountCustomRoles(ctx, tenantID); err == nil {
			out["custom_roles"] = int(n)
		}
	}
	if u.users != nil {
		if n, err := u.users.CountMonthlyActive(ctx, tenantID); err == nil {
			out[entitlements.LimitMAU] = n
		}
	}
	return out, nil
}

// importRoles lets a bulk user import give a role, with the checks assigning
// one to a person makes: the caller holds role.write and the role's authority,
// and a person's first role takes one of the plan's seats.
type importRoles struct {
	repo  *rbac.Repository
	seats rbac.SeatGuard
}

func (g importRoles) CheckGrant(r *http.Request, tenantID, roleID uuid.UUID) (int, error) {
	caller := httpx.PrincipalFromCtx(r.Context())
	ok, err := rbac.Holds(r.Context(), g.repo, caller, "role.write")
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errs.ErrRBACPermissionDenied.WithDetail("giving a role needs role.write")
	}
	if err := g.repo.CheckGrantRole(r.Context(), caller, tenantID, roleID); err != nil {
		return 0, err
	}
	return g.seats.SeatLimit(r.Context(), tenantID)
}

func (g importRoles) Assign(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID, seats int) error {
	return g.seats.WithinSeats(ctx, tx, tenantID, seats, func() error {
		return g.repo.AssignRole(ctx, tx, userID, tenantID, roleID, grantedBy)
	})
}

// streamAccess decides, while an activity stream is open, whether its reader
// may still read it, as the request was admitted: the access token unexpired
// and its session still live, the service principal or agent still enabled,
// the API key still valid, and the stream route's policy still met (through
// checker, as rbac.Enforce asks it).
type streamAccess struct {
	verifier *httpx.AuthVerifier
	checker  rbac.Checker
	apiKeys  *apikey.Service
	policy   rbac.RoutePolicy
}

func (a streamAccess) Allowed(ctx context.Context, p *httpx.Principal) (bool, error) {
	if p == nil || (p.ExpiresAt != nil && !time.Now().Before(*p.ExpiresAt)) {
		return false, nil
	}
	switch {
	case p.ActorType == "api_key":
		id, ok := subjectID(p)
		if !ok || p.TenantID == nil {
			return false, nil
		}
		if live, err := a.apiKeys.Live(ctx, *p.TenantID, id); err != nil || !live {
			return false, err
		}
	case p.ActorType == "service" && a.verifier.PrincipalLive != nil:
		id, ok := subjectID(p)
		if !ok {
			return false, nil
		}
		if live, err := a.verifier.PrincipalLive(ctx, id); err != nil || !live {
			return false, err
		}
	case p.AgentID != nil && a.verifier.AgentStatus != nil:
		if status, err := a.verifier.AgentStatus(ctx, *p.AgentID); err != nil || status != "active" {
			return false, err
		}
	case p.SessionID != nil && p.UserID != nil && p.ClientID == "" && a.verifier.SessionLive != nil:
		if live, err := a.verifier.SessionLive(ctx, *p.SessionID, *p.UserID); err != nil || !live {
			return false, err
		}
	}
	return rbac.Allows(ctx, a.checker, p, a.policy)
}

// subjectID is the id a machine credential's principal names as its subject;
// ok is false for one that isn't an id, which no credential of it can be.
func subjectID(p *httpx.Principal) (id uuid.UUID, ok bool) {
	id, err := uuid.Parse(p.Subject)
	return id, err == nil
}
