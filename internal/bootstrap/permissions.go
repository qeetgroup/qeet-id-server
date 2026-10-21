package bootstrap

import (
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
)

// userPermissionMap is the user-permission portion of the authorization policy
// table consumed by rbac.Enforce. RoutePolicies adds explicit self-service and
// handler-authorized routes; anything absent from the combined table is denied.
//
// Convention: reads → <resource>.read, mutations → <resource>.write. Built-in
// roles: owner/admin hold every permission; member holds only the four basic
// reads (tenant/user/role/group .read), so members can browse the org but
// cannot mutate it or read sensitive surfaces (audit, secrets, keys, SSO,
// billing, analytics, webhooks).
//
// NB: keys MUST match chi's composed RoutePattern (the "/v1" prefix included).
// A missing mutation entry = a silently ungated write, so keep this exhaustive.
func userPermissionMap() map[string]string {
	return map[string]string{
		// Tenants (GET /v1/tenants lists the caller's own memberships — ungated).
		"GET /v1/tenants/{tenantID}":    "tenant.read",
		"PATCH /v1/tenants/{tenantID}":  "tenant.write",
		"DELETE /v1/tenants/{tenantID}": "tenant.write",

		// Users.
		"GET /v1/users":                    "user.read",
		"GET /v1/users/stats":              "user.read",
		"GET /v1/users/trends":             "user.read",
		"POST /v1/users":                   "user.write",
		"POST /v1/users/bulk":              "user.write",
		"POST /v1/users/bulk/import":       "user.write",
		"GET /v1/users/deleted":            "user.read",
		"GET /v1/users/suspended":          "user.read",
		"POST /v1/users/{id}/reactivate":   "user.write",
		"PUT /v1/users/{id}/suspension":    "user.write",
		"GET /v1/users/{id}":               "user.read",
		"PATCH /v1/users/{id}":             "user.write",
		"DELETE /v1/users/{id}":            "user.write",
		"DELETE /v1/users/{id}/membership": "user.write",
		"POST /v1/users/{id}/restore":      "user.write",
		"DELETE /v1/users/{id}/purge":      "user.write",
		"POST /v1/users/{id}/password":     "user.write",
		"DELETE /v1/users/{id}/mfa":        "user.write", // admin MFA reset (Phase 3 feature)
		// A member's remembered devices, in the administrator's organisation.
		"GET /v1/users/{id}/trusted-devices":               "user.read",
		"DELETE /v1/users/{id}/trusted-devices":            "user.write",
		"DELETE /v1/users/{id}/trusted-devices/{deviceID}": "user.write",
		// A member's linked phones, in the administrator's organisation.
		"GET /v1/users/{id}/push-devices":               "user.read",
		"DELETE /v1/users/{id}/push-devices/{deviceID}": "user.write",

		// User 360 — per-user admin read surfaces + force sign-out (see user360.go).
		"GET /v1/users/{id}/security":             "user.read",
		"GET /v1/users/{id}/sessions":             "user.read",
		"GET /v1/users/{id}/access":               "user.read",
		"POST /v1/users/{id}/sessions/revoke-all": "user.write",
		"PUT /v1/users/{id}/mfa-required":         "user.write",

		// Invites (inviting/removing members is user management).
		"POST /v1/invites":                   "user.write",
		"GET /v1/tenants/{tenantID}/invites": "user.read",
		"POST /v1/invites/{id}/resend":       "user.write",
		"DELETE /v1/invites/{id}":            "user.write",

		// RBAC: roles, permissions, assignments, checks.
		"GET /v1/permissions":                                         "role.read",
		"GET /v1/tenants/{tenantID}/roles":                            "role.read",
		"POST /v1/tenants/{tenantID}/roles":                           "role.write",
		"GET /v1/roles/{roleID}/permissions":                          "role.read",
		"POST /v1/roles/{roleID}/permissions/{permID}":                "role.write",
		"DELETE /v1/roles/{roleID}/permissions/{permID}":              "role.write",
		"POST /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}":   "role.write",
		"DELETE /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}": "role.write",
		"GET /v1/users/{userID}/tenants/{tenantID}/permissions":       "role.read",
		"GET /v1/check": "role.read",
		"GET /v1/tenants/{tenantID}/groups/{groupID}/roles": "role.read",

		// ABAC: attribute-based access control policy CRUD.
		// Reads are gated on policy.read; mutations on policy.write. The
		// evaluate endpoint is a PDP call and is ungated beyond tenant scope
		// (it gates itself via requirePathTenant in the handler).
		"GET /v1/tenants/{tenantID}/abac/policies":         "policy.read",
		"POST /v1/tenants/{tenantID}/abac/policies":        "policy.write",
		"GET /v1/tenants/{tenantID}/abac/policies/{id}":    "policy.read",
		"PATCH /v1/tenants/{tenantID}/abac/policies/{id}":  "policy.write",
		"DELETE /v1/tenants/{tenantID}/abac/policies/{id}": "policy.write",
		"POST /v1/tenants/{tenantID}/abac/evaluate":        "policy.read",
		"POST /v1/tenants/{tenantID}/access/v1/evaluation": "role.read",

		// ReBAC: relationship tuples + identity graph.
		// Reads are gated on role.read (structural authz data). Writes/deletes
		// and the /check endpoint are ungated beyond tenant scope (they gate
		// themselves via requirePathTenant + the relation-tuple payload).
		"GET /v1/tenants/{tenantID}/relation-tuples":                    "role.read",
		"POST /v1/tenants/{tenantID}/relation-tuples":                   "role.write",
		"DELETE /v1/tenants/{tenantID}/relation-tuples/{id}":            "role.write",
		"POST /v1/tenants/{tenantID}/relation-tuples/check":             "role.read",
		"GET /v1/tenants/{tenantID}/relation-tuples/graph":              "role.read",
		"POST /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}":   "role.write",
		"DELETE /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}": "role.write",

		// Groups.
		"POST /v1/groups":                         "group.write",
		"GET /v1/tenants/{tenantID}/groups":       "group.read",
		"DELETE /v1/groups/{id}":                  "group.write",
		"PATCH /v1/groups/{id}":                   "group.write",
		"POST /v1/groups/{id}/members/{userID}":   "group.write",
		"DELETE /v1/groups/{id}/members/{userID}": "group.write",
		"GET /v1/groups/{id}/members":             "group.read",
		// Reusable group-shape templates and bulk import. Applying a template
		// and importing both create groups, so they take the write permission.
		"GET /v1/groups/templates":             "group.read",
		"POST /v1/groups/templates":            "group.write",
		"DELETE /v1/groups/templates/{id}":     "group.write",
		"POST /v1/groups/templates/{id}/apply": "group.write",
		"POST /v1/groups/import":               "group.write",

		// API keys + service principals (M2M).
		"POST /v1/api-keys":                             "apikey.write",
		"GET /v1/tenants/{tenantID}/api-keys":           "apikey.read",
		"DELETE /v1/api-keys/{id}":                      "apikey.write",
		"POST /v1/service-principals":                   "apikey.write",
		"GET /v1/tenants/{tenantID}/service-principals": "apikey.read",
		"DELETE /v1/service-principals/{id}":            "apikey.write",

		// SSO / identity connections: OIDC clients + grants/devices.
		"GET /v1/oidc/signing-keys":                                   "connection.read",
		"POST /v1/oidc/clients":                                       "connection.write",
		"DELETE /v1/oidc/clients/{id}":                                "connection.write",
		"GET /v1/tenants/{tenantID}/oidc/clients":                     "connection.read",
		"POST /v1/tenants/{tenantID}/oidc/clients":                    "connection.write",
		"GET /v1/tenants/{tenantID}/oidc/clients/{id}":                "connection.read",
		"PATCH /v1/tenants/{tenantID}/oidc/clients/{id}":              "connection.write",
		"GET /v1/tenants/{tenantID}/oidc/clients/{id}/auth-failures":  "connection.read",
		"GET /v1/tenants/{tenantID}/oidc/resources":                   "connection.read",
		"POST /v1/tenants/{tenantID}/oidc/resources":                  "connection.write",
		"DELETE /v1/tenants/{tenantID}/oidc/resources/{id}":           "connection.write",
		"DELETE /v1/tenants/{tenantID}/oidc/clients/{id}":             "connection.write",
		"POST /v1/tenants/{tenantID}/oidc/clients/{id}/rotate-secret": "connection.write",
		"GET /v1/tenants/{tenantID}/oidc/clients/shadow-ai":           "connection.read",
		"POST /v1/tenants/{tenantID}/oidc/clients/{id}/review":        "connection.write",
		"GET /v1/tenants/{tenantID}/oauth/grants":                     "connection.read",
		"DELETE /v1/tenants/{tenantID}/oauth/grants/{id}":             "connection.write",
		"GET /v1/tenants/{tenantID}/oauth/devices":                    "connection.read",
		// Tenant-wide trusted-device estate (adaptive MFA "remember this
		// device"), distinct from the OAuth device-grant flows above.
		"GET /v1/auth/trusted-devices/count":               "connection.read",
		"DELETE /v1/tenants/{tenantID}/oauth/devices/{id}": "connection.write",

		// SSO connections: SAML / SCIM / LDAP / social provider config.
		"GET /v1/tenants/{tenantID}/saml":                                                         "connection.read",
		"POST /v1/tenants/{tenantID}/saml":                                                        "connection.write",
		"GET /v1/tenants/{tenantID}/saml/{id}":                                                    "connection.read",
		"PATCH /v1/tenants/{tenantID}/saml/{id}":                                                  "connection.write",
		"POST /v1/tenants/{tenantID}/saml/{id}/test":                                              "connection.write",
		"DELETE /v1/tenants/{tenantID}/saml/{id}":                                                 "connection.write",
		"GET /v1/tenants/{tenantID}/saml-providers":                                               "connection.read",
		"POST /v1/tenants/{tenantID}/saml-providers":                                              "connection.write",
		"GET /v1/tenants/{tenantID}/saml-providers/{id}":                                          "connection.read",
		"PATCH /v1/tenants/{tenantID}/saml-providers/{id}":                                        "connection.write",
		"DELETE /v1/tenants/{tenantID}/saml-providers/{id}":                                       "connection.write",
		"GET /v1/tenants/{tenantID}/scim":                                                         "connection.read",
		"GET /v1/tenants/{tenantID}/directory/connections":                                        "connection.read",
		"GET /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings":                "connection.read",
		"POST /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings":               "connection.write",
		"POST /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings/preview":       "connection.read",
		"PUT /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}":    "connection.write",
		"DELETE /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}": "connection.write",
		"GET /v1/tenants/{tenantID}/directory/errors":                                             "connection.read",
		"POST /v1/tenants/{tenantID}/directory/errors/{eventID}/resolve":                          "connection.write",
		"POST /v1/tenants/{tenantID}/directory/errors/{eventID}/retry":                            "connection.write",
		"GET /v1/tenants/{tenantID}/directory/activity":                                           "connection.read",
		"POST /v1/tenants/{tenantID}/directory/alerts":                                            "connection.write",
		"POST /v1/tenants/{tenantID}/scim/token":                                                  "connection.write",
		"DELETE /v1/tenants/{tenantID}/scim/token":                                                "connection.write",
		"GET /v1/tenants/{tenantID}/scim/users":                                                   "connection.read",
		"POST /v1/tenants/{tenantID}/admin-portal/links":                                          "connection.write",
		"GET /v1/tenants/{tenantID}/admin-portal/links":                                           "connection.read",
		"DELETE /v1/tenants/{tenantID}/admin-portal/links/{id}":                                   "connection.write",
		"GET /v1/tenants/{tenantID}/ldap":                                                         "connection.read",
		"POST /v1/tenants/{tenantID}/ldap":                                                        "connection.write",
		"GET /v1/tenants/{tenantID}/ldap/{id}":                                                    "connection.read",
		"PATCH /v1/tenants/{tenantID}/ldap/{id}":                                                  "connection.write",
		"DELETE /v1/tenants/{tenantID}/ldap/{id}":                                                 "connection.write",
		"POST /v1/tenants/{tenantID}/ldap/{id}/test":                                              "connection.write",
		"GET /v1/tenants/{tenantID}/social/providers":                                             "connection.read",
		"POST /v1/social/providers":                                                               "connection.write",
		"PATCH /v1/social/providers/{provider}":                                                   "connection.write",
		"DELETE /v1/social/providers/{provider}":                                                  "connection.write",
		"GET /v1/users/{userID}/social/identities":                                                "user.read",
		"DELETE /v1/social/identities/{id}":                                                       "user.write",

		// Webhooks.
		"GET /v1/tenants/{tenantID}/webhooks":                  "webhook.read",
		"GET /v1/webhooks/{id}":                                "webhook.read",
		"GET /v1/webhooks/{id}/deliveries":                     "webhook.read",
		"POST /v1/webhooks":                                    "webhook.write",
		"DELETE /v1/webhooks/{id}":                             "webhook.write",
		"POST /v1/webhooks/{id}/test":                          "webhook.write",
		"POST /v1/webhooks/{id}/deliveries/{deliveryID}/retry": "webhook.write",

		// Secrets vault.
		"GET /v1/tenants/{tenantID}/secrets":              "secret.read",
		"POST /v1/tenants/{tenantID}/secrets":             "secret.write",
		"PATCH /v1/tenants/{tenantID}/secrets/{id}":       "secret.write",
		"DELETE /v1/tenants/{tenantID}/secrets/{id}":      "secret.write",
		"POST /v1/tenants/{tenantID}/secrets/{id}/reveal": "secret.read",

		// Third-party token-vault provider administration.
		"GET /v1/tenants/{tenantID}/vault/tokens/providers":               "secret.read",
		"POST /v1/tenants/{tenantID}/vault/tokens/providers":              "secret.write",
		"DELETE /v1/tenants/{tenantID}/vault/tokens/providers/{provider}": "secret.write",

		// Verifiable credentials.
		"GET /v1/tenants/{tenantID}/credentials":              "secret.read",
		"POST /v1/tenants/{tenantID}/credentials":             "secret.write",
		"POST /v1/tenants/{tenantID}/credentials/{id}/revoke": "secret.write",

		// Agent identities share the existing non-human identity permissions.
		"GET /v1/tenants/{tenantID}/agents":                                 "apikey.read",
		"POST /v1/tenants/{tenantID}/agents":                                "apikey.write",
		"POST /v1/tenants/{tenantID}/agents/kill-all":                       "apikey.write",
		"DELETE /v1/tenants/{tenantID}/agents/{id}":                         "apikey.write",
		"PATCH /v1/tenants/{tenantID}/agents/{id}":                          "apikey.write",
		"POST /v1/tenants/{tenantID}/agents/{id}/suspend":                   "apikey.write",
		"POST /v1/tenants/{tenantID}/agents/{id}/resume":                    "apikey.write",
		"POST /v1/tenants/{tenantID}/agents/{id}/decommission":              "apikey.write",
		"GET /v1/tenants/{tenantID}/agents/sponsored-by/{userID}":           "apikey.read",
		"POST /v1/tenants/{tenantID}/agents/sponsored-by/{userID}/transfer": "apikey.write",

		// Qeet AI provider config (BYOK) — org owner/admin only. Reuses the
		// secrets permission so a newly added capability need not be backfilled
		// onto existing owner roles. The other /qeetai/* routes are user-level.
		"GET /v1/qeetai/provider-config":       "secret.read",
		"PUT /v1/qeetai/provider-config":       "secret.write",
		"DELETE /v1/qeetai/provider-config":    "secret.write",
		"POST /v1/qeetai/provider-config/test": "secret.write",

		// Branding + email templates (GET branding is harmless — ungated).
		"PUT /v1/tenants/{tenantID}/branding":                       "branding.write",
		"PUT /v1/tenants/{tenantID}/email-templates/{key}":          "branding.write",
		"DELETE /v1/tenants/{tenantID}/email-templates/{key}":       "branding.write",
		"POST /v1/tenants/{tenantID}/email-templates/{key}/preview": "branding.write",
		"POST /v1/tenants/{tenantID}/email-templates/{key}/test":    "branding.write",
		"GET /v1/tenants/{tenantID}/branding":                       "tenant.read",
		"GET /v1/tenants/{tenantID}/email-templates":                "branding.write",
		"GET /v1/tenants/{tenantID}/email-templates/{key}":          "branding.write",

		// Security / auth policy, IP rules, retention.
		"GET /v1/tenants/{tenantID}/policy":                           "policy.read",
		"PUT /v1/tenants/{tenantID}/policy":                           "policy.write",
		"GET /v1/tenants/{tenantID}/auth-policy":                      "policy.read",
		"PUT /v1/tenants/{tenantID}/auth-policy":                      "policy.write",
		"GET /v1/tenants/{tenantID}/ip-rules":                         "policy.read",
		"POST /v1/tenants/{tenantID}/ip-rules":                        "policy.write",
		"DELETE /v1/tenants/{tenantID}/ip-rules/{ruleID}":             "policy.write",
		"PUT /v1/tenants/{tenantID}/ip-rules/config":                  "policy.write",
		"POST /v1/tenants/{tenantID}/ip-rules/check":                  "policy.read",
		"GET /v1/tenants/{tenantID}/retention":                        "policy.read",
		"PUT /v1/tenants/{tenantID}/retention":                        "policy.write",
		"POST /v1/tenants/{tenantID}/retention/preview":               "policy.read",
		"POST /v1/tenants/{tenantID}/retention/run":                   "policy.write",
		"GET /v1/tenants/{tenantID}/security/anomalies":               "policy.read",
		"GET /v1/tenants/{tenantID}/security/anomalies/summary":       "policy.read",
		"POST /v1/tenants/{tenantID}/security/anomalies/{id}/resolve": "policy.write",
		"GET /v1/tenants/{tenantID}/security/bots":                    "policy.read",
		"GET /v1/tenants/{tenantID}/security/bots/settings":           "policy.read",
		"PUT /v1/tenants/{tenantID}/security/bots/settings":           "policy.write",
		"GET /v1/tenants/{tenantID}/security/risk-settings":           "policy.read",
		"PUT /v1/tenants/{tenantID}/security/risk-settings":           "policy.write",
		"GET /v1/tenants/{tenantID}/rate-limits":                      "policy.read",
		"PUT /v1/tenants/{tenantID}/rate-limits":                      "policy.write",
		"DELETE /v1/tenants/{tenantID}/rate-limits":                   "policy.write",

		// Synchronous login hooks are tenant security policy.
		"GET /v1/tenants/{tenantID}/auth-hooks":         "policy.read",
		"POST /v1/tenants/{tenantID}/auth-hooks":        "policy.write",
		"PATCH /v1/tenants/{tenantID}/auth-hooks/{id}":  "policy.write",
		"DELETE /v1/tenants/{tenantID}/auth-hooks/{id}": "policy.write",

		// Verified domains affect hosted authentication routing.
		"GET /v1/tenants/{tenantID}/domains":              "connection.read",
		"POST /v1/tenants/{tenantID}/domains":             "connection.write",
		"POST /v1/tenants/{tenantID}/domains/{id}/verify": "connection.write",
		"DELETE /v1/tenants/{tenantID}/domains/{id}":      "connection.write",
		"PATCH /v1/tenants/{tenantID}/domains/{id}":       "connection.write",
		"GET /v1/tenants/{tenantID}/login-domain":         "connection.read",

		// GDPR.
		"POST /v1/gdpr/purge":                                         "gdpr.write",
		"GET /v1/tenants/{tenantID}/gdpr/purge":                       "gdpr.write",
		"DELETE /v1/gdpr/purge/{id}":                                  "gdpr.write",
		"POST /v1/gdpr/export":                                        "gdpr.write",
		"GET /v1/tenants/{tenantID}/gdpr/export":                      "gdpr.write",
		"GET /v1/tenants/{tenantID}/gdpr/export/{id}":                 "gdpr.write",
		"POST /v1/tenants/{tenantID}/compliance/{framework}/evidence": "audit.write",
		"GET /v1/tenants/{tenantID}/compliance/{framework}/evidence":  "audit.read",
		"GET /v1/tenants/{tenantID}/compliance/evidence/{id}":         "audit.read",

		// Audit (sensitive read).
		"GET /v1/tenants/{tenantID}/audit":        "audit.read",
		"GET /v1/tenants/{tenantID}/audit/verify": "audit.read",

		// Live Activity feed — sourced from the audit log; same sensitivity.
		"GET /v1/activity":              "audit.read",
		"GET /v1/activity/summary":      "audit.read",
		"GET /v1/activity/stream":       "audit.read",
		"GET /v1/activity/{id}/related": "audit.read",

		// Audit intelligence: behavioral-baseline anomaly detection over audit.events.
		"GET /v1/tenants/{tenantID}/audit/anomalies":               "audit.read",
		"GET /v1/tenants/{tenantID}/audit/anomalies/summary":       "audit.read",
		"POST /v1/tenants/{tenantID}/audit/anomalies/{id}/resolve": "audit.write",
		"GET /v1/tenants/{tenantID}/audit/anomaly-settings":        "audit.read",
		"PUT /v1/tenants/{tenantID}/audit/anomaly-settings":        "audit.write",

		// Billing (GET /v1/billing/plans is a public catalog — ungated).
		"GET /v1/tenants/{tenantID}/billing/subscription":         "billing.read",
		"PUT /v1/tenants/{tenantID}/billing/subscription":         "billing.write",
		"POST /v1/tenants/{tenantID}/billing/subscription/cancel": "billing.write",
		"GET /v1/tenants/{tenantID}/billing/invoices":             "billing.read",
		"GET /v1/tenants/{tenantID}/billing/profile":              "billing.read",
		"PUT /v1/tenants/{tenantID}/billing/profile":              "billing.write",
		"POST /v1/tenants/{tenantID}/billing/trial":               "billing.write",
		"POST /v1/tenants/{tenantID}/billing/checkout":            "billing.write",
		"GET /v1/tenants/{tenantID}/entitlements":                 "billing.read",
		"GET /v1/tenants/{tenantID}/entitlements/usage":           "billing.read",

		// Analytics.
		"GET /v1/tenants/{tenantID}/analytics/overview": "analytics.read",

		// Email delivery: whether the organisation's mail arrived (support),
		// and lifting a suppression its mail caused (administrators).
		"GET /v1/tenants/{tenantID}/email/messages":             "user.read",
		"GET /v1/tenants/{tenantID}/email/suppressions":         "user.read",
		"DELETE /v1/tenants/{tenantID}/email/suppressions/{id}": "user.write",

		// SIEM/log streaming contains tenant audit data.
		"GET /v1/tenants/{tenantID}/log-sinks":         "audit.read",
		"POST /v1/tenants/{tenantID}/log-sinks":        "audit.write",
		"PATCH /v1/tenants/{tenantID}/log-sinks/{id}":  "audit.write",
		"DELETE /v1/tenants/{tenantID}/log-sinks/{id}": "audit.write",
	}
}

// RoutePolicies is the authorization policy of every authenticated route,
// keyed "METHOD /v1/pattern", as rbac.Enforce applies it.
//
// Each policy names the scope an application's token needs on the route
// (rbac.RoutePolicy.ApplicationScope; TestEveryRouteNamesAnApplicationScope):
// the permission itself on an administrative route, account.read or
// account.write on the user's own account, openid on userinfo. Only the routes
// in ApplicationTokenRoutes accept an application's token in the first place.
func RoutePolicies() map[string]rbac.RoutePolicy {
	policies := make(map[string]rbac.RoutePolicy)
	for route, permission := range userPermissionMap() {
		policies[route] = rbac.PermissionPolicy(permission)
	}

	// Explicit user-only routes. These are self-service or personal resources;
	// machine principals cannot inherit them merely by carrying a user id.
	for _, route := range []string{
		"POST /v1/auth/logout",
		"POST /v1/auth/switch-tenant",
		"GET /v1/auth/sessions",
		"POST /v1/auth/sessions/revoke-others",
		"POST /v1/auth/sessions/revoke-all",
		"DELETE /v1/auth/sessions/{id}",
		"GET /v1/auth/trusted-devices",
		"DELETE /v1/auth/trusted-devices",
		"DELETE /v1/auth/trusted-devices/{id}",
		"GET /v1/auth/me",
		"GET /v1/auth/password",
		"GET /v1/auth/sign-in-methods",
		"POST /v1/auth/password",
		"GET /v1/me",
		"PATCH /v1/me",
		"GET /v1/tenants",
		"GET /v1/me/organizations",
		"POST /v1/tenants",
		"GET /v1/me/invites",
		"POST /v1/me/invites/accept",
		"POST /v1/me/invites/{id}/accept",
		"POST /v1/me/invites/{id}/decline",
		"POST /v1/users/{id}/verify/email/start",
		"POST /v1/users/{id}/verify/email/confirm",
		"POST /v1/users/{id}/verify/phone/start",
		"POST /v1/users/{id}/verify/phone/confirm",
		"POST /v1/me/email/change/start",
		"POST /v1/me/email/change/confirm",
		"GET /v1/passkeys",
		"PATCH /v1/passkeys/{id}",
		"DELETE /v1/passkeys/{id}",
		"POST /v1/passkeys/register/begin",
		"POST /v1/passkeys/register/finish",
		"GET /v1/mfa/totp",
		"POST /v1/mfa/totp/enroll/start",
		"POST /v1/mfa/totp/enroll/confirm",
		"POST /v1/mfa/totp/verify",
		"DELETE /v1/mfa/totp",
		"GET /v1/mfa/recovery-codes",
		"POST /v1/mfa/recovery-codes/regenerate",
		"GET /v1/mfa/otp/factors",
		"POST /v1/mfa/otp/factors",
		"POST /v1/mfa/otp/factors/{id}/confirm",
		"POST /v1/mfa/otp/factors/{id}/challenge",
		"DELETE /v1/mfa/otp/factors/{id}",
		"POST /v1/mfa/otp/verify",
		"POST /v1/mfa/webauthn/challenge",
		"POST /v1/mfa/webauthn/verify",
		"GET /v1/mfa/push/devices",
		"POST /v1/mfa/push/devices",
		"DELETE /v1/mfa/push/devices/{id}",
		"POST /v1/mfa/push/pairing",
		"GET /v1/mfa/push/pairing/{id}",
		"DELETE /v1/mfa/push/pairing/{id}",
		"GET /v1/mfa/step-up/status",
		"GET /v1/oauth/userinfo",
		"POST /v1/oauth/userinfo",
		"GET /v1/oauth/bc-authorize/pending",
		"POST /v1/oauth/bc-authorize/decision",
		"GET /v1/me/social/identities",
		"DELETE /v1/me/social/identities/{id}",
		"POST /v1/social/{provider}/link/start",
		"GET /v1/vault/tokens",
		"GET /v1/vault/tokens/{provider}/connect",
		"DELETE /v1/vault/tokens/{provider}",
		"GET /v1/notifications",
		"POST /v1/notifications/mark-all-read",
		"POST /v1/account/export",
		"POST /v1/account/delete",
		"GET /v1/billing/plans",
		"POST /v1/signup/checkout",
		"GET /v1/qeetai/status",
		"POST /v1/qeetai/conversations",
		"GET /v1/qeetai/conversations",
		"GET /v1/qeetai/conversations/{conversationID}",
		"PATCH /v1/qeetai/conversations/{conversationID}",
		"DELETE /v1/qeetai/conversations/{conversationID}",
		"POST /v1/qeetai/conversations/{conversationID}/messages",
		"POST /v1/sales/leads",
	} {
		policies[route] = rbac.UserOnlyPolicy(accountScope(route))
	}
	// Userinfo is the one route made for applications (ApplicationTokenRoutes),
	// and OpenID Connect needs openid of a token reading it.
	policies["GET /v1/oauth/userinfo"] = rbac.UserOnlyPolicy("openid")
	policies["POST /v1/oauth/userinfo"] = rbac.UserOnlyPolicy("openid")

	// These routes derive a vault:<resource> scope from the path and enforce it
	// in the handler; the central catalogue still classifies the actor surface.
	policies["GET /v1/vault/{name}"] = rbac.HandlerAuthorizedPolicy(true, "vault:read")
	policies["GET /v1/vault/tokens/{provider}/access-token"] = rbac.HandlerAuthorizedPolicy(true, "vault:read")

	// Search performs per-result-type RBAC checks in its service. Keep it user
	// only until an equivalent per-type machine-scope evaluator is implemented.
	policies["GET /v1/search"] = rbac.UserOnlyPolicy("user.read")
	return policies
}

// accountScope is the scope an application's token needs on a route of the
// user's own account: account.read to read it, account.write to change it.
func accountScope(route string) string {
	if strings.HasPrefix(route, "GET ") {
		return "account.read"
	}
	return "account.write"
}
