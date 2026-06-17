package http

// permissionMap is the authorization policy table consumed by rbac.Enforce:
// "METHOD /chi/route/pattern" → required permission. Only end-user principals
// are gated (API keys / service principals bypass — see rbac.Enforce); routes
// absent here are ungated (public, self-service, or tenant-create).
//
// Convention: reads → <resource>.read, mutations → <resource>.write. Built-in
// roles: owner/admin hold every permission; member holds only the four basic
// reads (tenant/user/role/group .read), so members can browse the org but
// cannot mutate it or read sensitive surfaces (audit, secrets, keys, SSO,
// billing, analytics, webhooks).
//
// NB: keys MUST match chi's composed RoutePattern (the "/v1" prefix included).
// A missing mutation entry = a silently ungated write, so keep this exhaustive.
func permissionMap() map[string]string {
	return map[string]string{
		// Tenants (GET /v1/tenants lists the caller's own memberships — ungated).
		"GET /v1/tenants/{id}":    "tenant.read",
		"PATCH /v1/tenants/{id}":  "tenant.write",
		"DELETE /v1/tenants/{id}": "tenant.write",

		// Users.
		"GET /v1/users":                "user.read",
		"POST /v1/users":               "user.write",
		"GET /v1/users/deleted":        "user.read",
		"GET /v1/users/{id}":           "user.read",
		"PATCH /v1/users/{id}":         "user.write",
		"DELETE /v1/users/{id}":        "user.write",
		"POST /v1/users/{id}/restore":  "user.write",
		"DELETE /v1/users/{id}/purge":  "user.write",
		"POST /v1/users/{id}/password": "user.write",
		"DELETE /v1/users/{id}/mfa":    "user.write", // admin MFA reset (Phase 3 feature)

		// Invites (inviting/removing members is user management).
		"POST /v1/invites":                   "user.write",
		"GET /v1/tenants/{tenantID}/invites": "user.read",
		"DELETE /v1/invites/{id}":            "user.write",

		// RBAC: roles, permissions, assignments, checks.
		"GET /v1/permissions":                                         "role.read",
		"GET /v1/tenants/{tenantID}/roles":                            "role.read",
		"POST /v1/tenants/{tenantID}/roles":                           "role.write",
		"POST /v1/roles/{roleID}/permissions/{permID}":                "role.write",
		"DELETE /v1/roles/{roleID}/permissions/{permID}":              "role.write",
		"POST /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}":   "role.write",
		"DELETE /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}": "role.write",
		"GET /v1/users/{userID}/tenants/{tenantID}/permissions":       "role.read",
		"GET /v1/check": "role.read",
		"GET /v1/tenants/{tenantID}/groups/{groupID}/roles":             "role.read",
		"POST /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}":   "role.write",
		"DELETE /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}": "role.write",

		// Groups.
		"POST /v1/groups":                         "group.write",
		"GET /v1/tenants/{tenantID}/groups":       "group.read",
		"DELETE /v1/groups/{id}":                  "group.write",
		"POST /v1/groups/{id}/members/{userID}":   "group.write",
		"DELETE /v1/groups/{id}/members/{userID}": "group.write",
		"GET /v1/groups/{id}/members":             "group.read",

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
		"GET /v1/tenants/{tenantID}/oidc/clients":                     "connection.read",
		"POST /v1/tenants/{tenantID}/oidc/clients":                    "connection.write",
		"GET /v1/tenants/{tenantID}/oidc/clients/{id}":                "connection.read",
		"PATCH /v1/tenants/{tenantID}/oidc/clients/{id}":              "connection.write",
		"DELETE /v1/tenants/{tenantID}/oidc/clients/{id}":             "connection.write",
		"POST /v1/tenants/{tenantID}/oidc/clients/{id}/rotate-secret": "connection.write",
		"GET /v1/tenants/{tenantID}/oauth/grants":                     "connection.read",
		"DELETE /v1/tenants/{tenantID}/oauth/grants/{id}":             "connection.write",
		"GET /v1/tenants/{tenantID}/oauth/devices":                    "connection.read",
		"DELETE /v1/tenants/{tenantID}/oauth/devices/{id}":            "connection.write",

		// SSO connections: SAML / SCIM / LDAP / social provider config.
		"GET /v1/tenants/{tenantID}/saml":                   "connection.read",
		"POST /v1/tenants/{tenantID}/saml":                  "connection.write",
		"GET /v1/tenants/{tenantID}/saml/{id}":              "connection.read",
		"PATCH /v1/tenants/{tenantID}/saml/{id}":            "connection.write",
		"DELETE /v1/tenants/{tenantID}/saml/{id}":           "connection.write",
		"GET /v1/tenants/{tenantID}/saml-providers":         "connection.read",
		"POST /v1/tenants/{tenantID}/saml-providers":        "connection.write",
		"GET /v1/tenants/{tenantID}/saml-providers/{id}":    "connection.read",
		"PATCH /v1/tenants/{tenantID}/saml-providers/{id}":  "connection.write",
		"DELETE /v1/tenants/{tenantID}/saml-providers/{id}": "connection.write",
		"GET /v1/tenants/{tenantID}/scim":                   "connection.read",
		"POST /v1/tenants/{tenantID}/scim/token":            "connection.write",
		"DELETE /v1/tenants/{tenantID}/scim/token":          "connection.write",
		"GET /v1/tenants/{tenantID}/scim/users":             "connection.read",
		"GET /v1/tenants/{tenantID}/ldap":                   "connection.read",
		"POST /v1/tenants/{tenantID}/ldap":                  "connection.write",
		"GET /v1/tenants/{tenantID}/ldap/{id}":              "connection.read",
		"PATCH /v1/tenants/{tenantID}/ldap/{id}":            "connection.write",
		"DELETE /v1/tenants/{tenantID}/ldap/{id}":           "connection.write",
		"POST /v1/tenants/{tenantID}/ldap/{id}/test":        "connection.write",
		"GET /v1/tenants/{tenantID}/social/providers":       "connection.read",
		"POST /v1/tenants/{tenantID}/social/providers":      "connection.write",

		// Webhooks.
		"GET /v1/tenants/{tenantID}/webhooks": "webhook.read",
		"POST /v1/webhooks":                   "webhook.write",
		"DELETE /v1/webhooks/{id}":            "webhook.write",
		"POST /v1/webhooks/{id}/test":         "webhook.write",

		// Secrets vault.
		"GET /v1/tenants/{tenantID}/secrets":              "secret.read",
		"POST /v1/tenants/{tenantID}/secrets":             "secret.write",
		"PATCH /v1/tenants/{tenantID}/secrets/{id}":       "secret.write",
		"DELETE /v1/tenants/{tenantID}/secrets/{id}":      "secret.write",
		"POST /v1/tenants/{tenantID}/secrets/{id}/reveal": "secret.read",

		// Branding + email templates (GET branding is harmless — ungated).
		"PUT /v1/tenants/{tenantID}/branding":                       "branding.write",
		"PUT /v1/tenants/{tenantID}/email-templates/{key}":          "branding.write",
		"DELETE /v1/tenants/{tenantID}/email-templates/{key}":       "branding.write",
		"POST /v1/tenants/{tenantID}/email-templates/{key}/preview": "branding.write",

		// Security / auth policy, IP rules, retention.
		"GET /v1/tenants/{tenantID}/policy":               "policy.read",
		"PUT /v1/tenants/{tenantID}/policy":               "policy.write",
		"GET /v1/tenants/{tenantID}/auth-policy":          "policy.read",
		"PUT /v1/tenants/{tenantID}/auth-policy":          "policy.write",
		"GET /v1/tenants/{tenantID}/ip-rules":             "policy.read",
		"POST /v1/tenants/{tenantID}/ip-rules":            "policy.write",
		"DELETE /v1/tenants/{tenantID}/ip-rules/{ruleID}": "policy.write",
		"PUT /v1/tenants/{tenantID}/ip-rules/config":      "policy.write",
		"POST /v1/tenants/{tenantID}/ip-rules/check":      "policy.read",
		"GET /v1/tenants/{tenantID}/retention":            "policy.read",
		"PUT /v1/tenants/{tenantID}/retention":            "policy.write",
		"POST /v1/tenants/{tenantID}/retention/preview":   "policy.read",
		"POST /v1/tenants/{tenantID}/retention/run":       "policy.write",

		// GDPR.
		"POST /v1/gdpr/purge":                   "gdpr.write",
		"GET /v1/tenants/{tenantID}/gdpr/purge": "gdpr.write",
		"DELETE /v1/gdpr/purge/{id}":            "gdpr.write",

		// Audit (sensitive read).
		"GET /v1/tenants/{tenantID}/audit":        "audit.read",
		"GET /v1/tenants/{tenantID}/audit/verify": "audit.read",
		"GET /v1/admin/outbox/dlq":                "audit.read",

		// Billing (GET /v1/billing/plans is a public catalog — ungated).
		"GET /v1/tenants/{tenantID}/billing/subscription":         "billing.read",
		"PUT /v1/tenants/{tenantID}/billing/subscription":         "billing.write",
		"POST /v1/tenants/{tenantID}/billing/subscription/cancel": "billing.write",
		"GET /v1/tenants/{tenantID}/billing/invoices":             "billing.read",

		// Analytics.
		"GET /v1/tenants/{tenantID}/analytics/overview": "analytics.read",
	}
}
