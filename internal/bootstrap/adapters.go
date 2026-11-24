package bootstrap

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/overview"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// billingOrgProvisioner adapts the organization repository to billing.OrgProvisioner,
// so billing can create an organization after a paid checkout.
type billingOrgProvisioner struct{ organizations *organization.Repository }

func (p billingOrgProvisioner) ProvisionOrg(ctx context.Context, ownerID uuid.UUID, name, slug, region, plan string) (uuid.UUID, error) {
	t, err := p.organizations.CreateWithOwner(ctx, organization.CreateInput{Slug: slug, Name: name, Plan: plan, Region: region}, ownerID)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// planResolver is an organization's effective plan as billing decides it, the
// plan label its record carries standing in when it has no subscription.
func planResolver(billingService *billing.Service, organizations *organization.Repository) billing.PlanResolver {
	return billing.PlanResolver{Billing: billingService, Label: func(ctx context.Context, organizationID uuid.UUID) (string, error) {
		o, err := organizations.Get(ctx, organizationID)
		if err != nil {
			return "", err
		}
		return o.Plan, nil
	}}
}

// entitlementUsageResolver reports an organization's current consumption for the
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

func (u entitlementUsageResolver) Usage(ctx context.Context, organizationID uuid.UUID) (map[string]int, error) {
	out := map[string]int{}
	if u.invites != nil {
		if n, err := u.invites.CountSeats(ctx, organizationID); err == nil {
			out[entitlements.LimitSeats] = n
		}
	}
	if u.oidc != nil {
		if n, err := u.oidc.CountClients(ctx, organizationID); err == nil {
			out[entitlements.LimitApps] = n
		}
	}
	if u.apikeys != nil {
		if n, err := u.apikeys.CountActive(ctx, organizationID); err == nil {
			out[entitlements.LimitAPIKeys] = n
		}
	}
	if u.rbacRepo != nil {
		if n, err := u.rbacRepo.CountCustomRoles(ctx, organizationID); err == nil {
			out[entitlements.LimitCustomRoles] = int(n)
		}
	}
	if u.users != nil {
		if n, err := u.users.CountMonthlyActive(ctx, organizationID); err == nil {
			out[entitlements.LimitMAU] = n
		}
	}
	return out, nil
}

// overviewAccess decides which of the overview's areas a caller may read: an
// area needing a permission is theirs when a route needing it would admit
// them, as the route guard decides it.
func overviewAccess(checker rbac.Checker) overview.Authorizer {
	return func(ctx context.Context, p *httpx.Principal, permission string) (bool, error) {
		if p == nil {
			return false, nil
		}
		return rbac.Allows(ctx, checker, p, rbac.PermissionPolicy(permission))
	}
}

// streamAccess decides, while an activity stream is open, whether its reader
// may still read it, as the request was admitted: still live as verifier
// decides, and still meeting the stream route's policy (through checker, as
// rbac.Enforce asks it).
func streamAccess(verifier *httpx.AuthVerifier, checker rbac.Checker, policy rbac.RoutePolicy) func(ctx context.Context, p *httpx.Principal) (bool, error) {
	return func(ctx context.Context, p *httpx.Principal) (bool, error) {
		if live, err := verifier.Live(ctx, p); err != nil || !live {
			return false, err
		}
		return rbac.Allows(ctx, checker, p, policy)
	}
}
