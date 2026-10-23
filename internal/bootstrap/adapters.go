package bootstrap

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
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
			switch sub.Status {
			case "active", "past_due":
				return sub.PlanCode, nil
			case "trialing":
				// Trial grants the tier only until it expires; afterwards the
				// tenant reverts to free (evaluated lazily here — no scheduler).
				if sub.TrialEnd != nil && sub.TrialEnd.After(time.Now()) {
					return sub.PlanCode, nil
				}
				return "free", nil
			default:
				// canceled / unknown: a subscription row exists but isn't granting,
				// so this is a paid org that lapsed — free, not the stale label.
				return "free", nil
			}
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
	return out, nil
}
