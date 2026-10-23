// Package entitlements maps a tenant's plan to its capabilities: boolean
// features such as SSO, SCIM and webhooks, and numeric limits such as seats,
// apps and API keys. Backend enforcement points and the console both read it,
// so they agree on what a plan includes. Catalog defines the tiers.
package entitlements

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Boolean feature keys. FeatureSSO covers sign-in through an external SAML or
// OIDC identity provider.
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
	FeatureSSO            = "sso"
	FeatureSCIM           = "scim"
	FeatureLDAP           = "ldap"
	FeatureWebhooks       = "webhooks"
	FeatureAuditExport    = "audit_export"
	FeatureAIQeetai       = "ai_qeetai"
	FeatureABAC           = "abac"
)

// Numeric limit keys. Unlimited (-1) = no cap; 0 = none allowed.
const (
	LimitSeats              = "seats"                // active members plus pending invites
	LimitApps               = "apps"                 // OIDC relying parties
	LimitAPIKeys            = "api_keys"             // API keys
	LimitCustomRoles        = "custom_roles"         // roles beyond the built-in ones
	LimitWebhooks           = "webhooks"             // webhook endpoints
	LimitOrgs               = "orgs"                 // organizations
	LimitMAU                = "mau"                  // monthly active users
	LimitAuditRetentionDays = "audit_retention_days" // days of audit history kept
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

// features returns a map of every feature key, true for the keys in on. Every
// key is present in every tier, so a missing key is never mistaken for "off".
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

// coreLogin lists the sign-in features every plan includes, free too.
var coreLogin = []string{
	FeaturePasskeys, FeaturePassword, FeatureMagicLinks, FeatureSocial,
	FeatureTOTP, FeatureEmailOTP, FeatureHostedLogin,
}

// Catalog maps a normalized plan code to its entitlements.
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

// NormalizePlan returns the catalog key of a plan code: lowercased, without the
// "_year" suffix. An unknown, empty or "none" code fails closed to "free".
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

// For returns a copy of the entitlements of a plan code.
func For(code string) Entitlements {
	return Catalog[NormalizePlan(code)].clone()
}

// PlanResolver returns a tenant's effective plan code, from its billing
// subscription or else its plan label. It keeps this package from importing
// billing and tenant.
type PlanResolver interface {
	EffectivePlan(ctx context.Context, tenantID uuid.UUID) (string, error)
}

// UsageResolver returns a tenant's current consumption, keyed like Limits
// (seats, apps, api_keys, …). It is optional and only feeds the billing usage
// display.
type UsageResolver interface {
	Usage(ctx context.Context, tenantID uuid.UUID) (map[string]int, error)
}

// Service answers entitlement questions for a tenant. Enforcement points use
// it through their own small interfaces.
type Service struct {
	resolver PlanResolver
	usage    UsageResolver
}

// NewService returns a Service that resolves plans with r. A nil r puts every
// tenant on the free tier.
func NewService(r PlanResolver) *Service { return &Service{resolver: r} }

// SetUsageResolver sets the optional usage provider. Without one, Usage reports
// nothing.
func (s *Service) SetUsageResolver(u UsageResolver) { s.usage = u }

// Usage returns the tenant's current consumption per resource, or an empty map
// without a usage provider.
func (s *Service) Usage(ctx context.Context, tenantID uuid.UUID) (map[string]int, error) {
	if s.usage == nil {
		return map[string]int{}, nil
	}
	return s.usage.Usage(ctx, tenantID)
}

// Resolve returns the tenant's entitlements. With a nil PlanResolver, or an
// unknown plan, that is the free tier.
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

// FeatureAllowed reports whether the tenant's plan includes feature.
func (s *Service) FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error) {
	ent, err := s.Resolve(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return ent.Features[feature], nil
}

// Limit returns the tenant's cap on resource. A resource the plan does not cap,
// or that is not modelled, is Unlimited: only deliberately gated resources have
// limits.
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
