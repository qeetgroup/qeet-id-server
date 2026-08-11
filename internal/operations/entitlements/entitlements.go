// Package entitlements turns a tenant's subscription plan into a machine-readable
// capability set: boolean feature flags (SSO, SCIM, webhooks, …) and numeric
// resource limits (seats, apps, api keys, …). It is the single source of truth
// both the backend enforcement points and the console read, so the UI and the
// server never disagree about what a plan includes.
//
// The catalog below encodes the published plan tiers. Only the FREE tier is
// enforced today; paid tiers are all-unlocked/unlimited enough that enforcement
// is a no-op for them (values still track the marketing so the console can gate
// higher tiers later without more code). Tune a tier by editing one map entry.
package entitlements

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Boolean feature keys.
const (
	FeaturePasskeys       = "passkeys"
	FeaturePassword       = "password"
	FeatureMagicLinks     = "magic_links"
	FeatureSocial         = "social"
	FeatureTOTP           = "totp"
	FeatureEmailOTP       = "email_otp"
	FeatureHostedLogin    = "hosted_login"
	FeatureSMSMFA         = "sms_mfa"
	FeatureCustomBranding = "custom_branding"
	FeatureCustomDomain   = "custom_domain"
	FeatureSSO            = "sso" // SAML / OIDC federation-in (external IdP login)
	FeatureSCIM           = "scim"
	FeatureLDAP           = "ldap"
	FeatureWebhooks       = "webhooks"
	FeatureAuditExport    = "audit_export"
	FeatureAIQeetai       = "ai_qeetai"
	FeatureABAC           = "abac"
)

// Numeric limit keys. Unlimited (-1) = no cap; 0 = none allowed.
const (
	LimitSeats              = "seats" // active members + pending invites
	LimitApps               = "apps"  // OIDC relying parties
	LimitAPIKeys            = "api_keys"
	LimitCustomRoles        = "custom_roles"
	LimitWebhooks           = "webhooks"
	LimitOrgs               = "orgs"
	LimitMAU                = "mau"
	LimitAuditRetentionDays = "audit_retention_days"
)

// Unlimited marks a numeric limit as uncapped.
const Unlimited = -1

// Entitlements is the resolved plan capability set for a tenant.
type Entitlements struct {
	Plan     string          `json:"plan"`
	Features map[string]bool `json:"features"`
	Limits   map[string]int  `json:"limits"`
}

func (e Entitlements) clone() Entitlements {
	f := make(map[string]bool, len(e.Features))
	for k, v := range e.Features {
		f[k] = v
	}
	l := make(map[string]int, len(e.Limits))
	for k, v := range e.Limits {
		l[k] = v
	}
	return Entitlements{Plan: e.Plan, Features: f, Limits: l}
}

// features builds a full feature map: everything false, then the passed keys true.
// Keeping every key present in every tier makes lookups deterministic (a missing
// key can't be mistaken for "off").
func features(on ...string) map[string]bool {
	all := []string{
		FeaturePasskeys, FeaturePassword, FeatureMagicLinks, FeatureSocial,
		FeatureTOTP, FeatureEmailOTP, FeatureHostedLogin, FeatureSMSMFA,
		FeatureCustomBranding, FeatureCustomDomain, FeatureSSO, FeatureSCIM,
		FeatureLDAP, FeatureWebhooks, FeatureAuditExport, FeatureAIQeetai, FeatureABAC,
	}
	m := make(map[string]bool, len(all))
	for _, k := range all {
		m[k] = false
	}
	for _, k := range on {
		m[k] = true
	}
	return m
}

// coreLogin are the auth primitives every plan (including free) includes.
var coreLogin = []string{
	FeaturePasskeys, FeaturePassword, FeatureMagicLinks, FeatureSocial,
	FeatureTOTP, FeatureEmailOTP, FeatureHostedLogin,
}

// Catalog maps a normalized plan code to its entitlements. Edit numbers/flags here.
var Catalog = map[string]Entitlements{
	"free": {
		Plan:     "free",
		Features: features(coreLogin...),
		Limits: map[string]int{
			LimitSeats:              5,
			LimitApps:               3,
			LimitAPIKeys:            2,
			LimitCustomRoles:        0,
			LimitWebhooks:           0,
			LimitOrgs:               1,
			LimitMAU:                10000,
			LimitAuditRetentionDays: 7,
		},
	},
	"starter": {
		Plan: "starter",
		Features: features(append(append([]string{}, coreLogin...),
			FeatureSMSMFA, FeatureCustomBranding, FeatureCustomDomain, FeatureWebhooks)...),
		Limits: map[string]int{
			LimitSeats:              Unlimited,
			LimitApps:               Unlimited,
			LimitAPIKeys:            Unlimited,
			LimitCustomRoles:        Unlimited,
			LimitWebhooks:           Unlimited,
			LimitOrgs:               Unlimited,
			LimitMAU:                25000,
			LimitAuditRetentionDays: 30,
		},
	},
	"pro": {
		Plan: "pro",
		Features: features(append(append([]string{}, coreLogin...),
			FeatureSMSMFA, FeatureCustomBranding, FeatureCustomDomain, FeatureWebhooks,
			FeatureSSO, FeatureAuditExport, FeatureAIQeetai, FeatureABAC)...),
		Limits: map[string]int{
			LimitSeats:              Unlimited,
			LimitApps:               Unlimited,
			LimitAPIKeys:            Unlimited,
			LimitCustomRoles:        Unlimited,
			LimitWebhooks:           Unlimited,
			LimitOrgs:               Unlimited,
			LimitMAU:                100000,
			LimitAuditRetentionDays: 90,
		},
	},
	"enterprise": {
		Plan: "enterprise",
		Features: features(FeaturePasskeys, FeaturePassword, FeatureMagicLinks, FeatureSocial,
			FeatureTOTP, FeatureEmailOTP, FeatureHostedLogin, FeatureSMSMFA,
			FeatureCustomBranding, FeatureCustomDomain, FeatureSSO, FeatureSCIM,
			FeatureLDAP, FeatureWebhooks, FeatureAuditExport, FeatureAIQeetai, FeatureABAC),
		Limits: map[string]int{
			LimitSeats:              Unlimited,
			LimitApps:               Unlimited,
			LimitAPIKeys:            Unlimited,
			LimitCustomRoles:        Unlimited,
			LimitWebhooks:           Unlimited,
			LimitOrgs:               Unlimited,
			LimitMAU:                Unlimited,
			LimitAuditRetentionDays: Unlimited,
		},
	},
}

// NormalizePlan folds a raw plan code to a catalog key: lowercased, "_year"
// suffix stripped, and any unknown / empty / "none" value fails closed to "free".
func NormalizePlan(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.TrimSuffix(code, "_year")
	switch code {
	case "free", "starter", "pro", "enterprise":
		return code
	default:
		return "free"
	}
}

// For returns a defensive copy of the entitlements for a (raw) plan code.
func For(code string) Entitlements {
	return Catalog[NormalizePlan(code)].clone()
}

// LimitReached reports whether one more of a resource would exceed the cap.
// A negative (Unlimited) limit is never reached.
func LimitReached(limit, current int) bool {
	return limit >= 0 && current >= limit
}

// PlanResolver returns a tenant's effective (raw) plan code. Implemented by the
// composition root, which reads the authoritative source (billing subscription
// with a fallback to the tenant plan label). Injected so this package doesn't
// import the billing/tenant contexts.
type PlanResolver interface {
	EffectivePlan(ctx context.Context, tenantID uuid.UUID) (string, error)
}

// UsageResolver returns a tenant's current consumption keyed by the same
// resource names as Limits (seats, apps, api_keys, custom_roles, …). Implemented
// by the composition root (which can reach every context's count query), so this
// package stays decoupled. Optional — used only for the billing usage display.
type UsageResolver interface {
	Usage(ctx context.Context, tenantID uuid.UUID) (map[string]int, error)
}

// Service resolves and answers entitlement questions for a tenant. It is the
// concrete type injected (as a small local interface) into every enforcement point.
type Service struct {
	resolver PlanResolver
	usage    UsageResolver
}

func NewService(r PlanResolver) *Service { return &Service{resolver: r} }

// SetUsageResolver wires the (optional) current-usage provider used by the
// billing usage endpoint. nil = usage reported as empty.
func (s *Service) SetUsageResolver(u UsageResolver) { s.usage = u }

// Usage returns the tenant's current consumption per resource (empty when no
// resolver is wired).
func (s *Service) Usage(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	if s.usage == nil {
		return map[string]int{}, nil
	}
	return s.usage.Usage(ctx, tenantID)
}

// Resolve returns the tenant's full entitlement set. A nil resolver (or a
// resolver returning an unknown plan) yields the free tier.
func (s *Service) Resolve(ctx context.Context, tenantID uuid.UUID) (Entitlements, error) {
	code := "free"
	if s.resolver != nil {
		c, err := s.resolver.EffectivePlan(ctx, tenantID)
		if err != nil {
			return Entitlements{}, err
		}
		code = c
	}
	return For(code), nil
}

// FeatureAllowed reports whether a boolean feature is included in the tenant's plan.
func (s *Service) FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error) {
	ent, err := s.Resolve(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return ent.Features[feature], nil
}

// Limit returns the numeric cap for a resource (Unlimited when the plan doesn't
// cap it, or when the resource isn't modelled — fail-open, since limits only
// exist for resources we deliberately gate).
func (s *Service) Limit(ctx context.Context, tenantID uuid.UUID, resource string) (int, error) {
	ent, err := s.Resolve(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	if v, ok := ent.Limits[resource]; ok {
		return v, nil
	}
	return Unlimited, nil
}
