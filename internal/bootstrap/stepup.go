package bootstrap

import "github.com/qeetgroup/qeet-id-server/internal/access/mfa"

// StepUpRoutes lists the authenticated routes that need a recent step-up, so a
// stolen access token alone can't change factors, credentials, secrets, policy or
// authority. StepUpWhenFactorHeld applies to a person's own factors; everything
// else is StepUpAlways, which machine principals can never meet.
func StepUpRoutes() map[string]mfa.StepUpRule {
	routes := map[string]mfa.StepUpRule{}
	for _, route := range []string{
		// The person's own factors and sign-in methods.
		"POST /v1/mfa/totp/enroll/start",
		"POST /v1/mfa/otp/factors",
		"DELETE /v1/mfa/otp/factors/{id}",
		"POST /v1/mfa/push/devices",
		"DELETE /v1/mfa/push/devices/{id}",
		"POST /v1/mfa/push/pairing",
		"POST /v1/passkeys/register/begin",
		"DELETE /v1/passkeys/{id}",
		"POST /v1/social/{provider}/link/start",
		"POST /v1/account/delete",
		// The address password resets and invitations go to.
		"POST /v1/me/email/change/start",
	} {
		routes[route] = mfa.StepUpWhenFactorHeld
	}
	for _, route := range []string{
		// Switching the authenticator app off, or replacing its recovery codes.
		"DELETE /v1/mfa/totp",
		"POST /v1/mfa/recovery-codes/regenerate",

		// Machine credentials.
		"POST /v1/api-keys",
		"DELETE /v1/api-keys/{id}",
		"POST /v1/service-principals",
		"DELETE /v1/service-principals/{id}",
		"POST /v1/tenants/{tenantID}/agents",
		"PATCH /v1/tenants/{tenantID}/agents/{id}",
		"DELETE /v1/tenants/{tenantID}/agents/{id}",
		"POST /v1/tenants/{tenantID}/agents/{id}/resume",
		"POST /v1/tenants/{tenantID}/agents/sponsored-by/{userID}/transfer",
		"POST /v1/oidc/clients",
		"DELETE /v1/oidc/clients/{id}",
		"POST /v1/tenants/{tenantID}/oidc/clients",
		"PATCH /v1/tenants/{tenantID}/oidc/clients/{id}",
		"DELETE /v1/tenants/{tenantID}/oidc/clients/{id}",
		"POST /v1/tenants/{tenantID}/oidc/clients/{id}/rotate-secret",
		"POST /v1/tenants/{tenantID}/scim/token",
		"DELETE /v1/tenants/{tenantID}/scim/token",
		"POST /v1/tenants/{tenantID}/credentials",
		"POST /v1/tenants/{tenantID}/credentials/{id}/revoke",
		"POST /v1/webhooks",
		"DELETE /v1/webhooks/{id}",
		"POST /v1/tenants/{tenantID}/auth-hooks",
		"PATCH /v1/tenants/{tenantID}/auth-hooks/{id}",
		"DELETE /v1/tenants/{tenantID}/auth-hooks/{id}",

		// Secrets and keys.
		"POST /v1/tenants/{tenantID}/secrets",
		"PATCH /v1/tenants/{tenantID}/secrets/{id}",
		"DELETE /v1/tenants/{tenantID}/secrets/{id}",
		"POST /v1/tenants/{tenantID}/secrets/{id}/reveal",
		"POST /v1/tenants/{tenantID}/vault/tokens/providers",
		"DELETE /v1/tenants/{tenantID}/vault/tokens/providers/{provider}",
		"PUT /v1/qeetai/provider-config",
		"DELETE /v1/qeetai/provider-config",

		// Sign-in and security policy.
		"PUT /v1/tenants/{tenantID}/policy",
		"PUT /v1/tenants/{tenantID}/auth-policy",
		"PUT /v1/tenants/{tenantID}/security/risk-settings",
		"PUT /v1/tenants/{tenantID}/security/bots/settings",
		"POST /v1/tenants/{tenantID}/ip-rules",
		"DELETE /v1/tenants/{tenantID}/ip-rules/{ruleID}",
		"PUT /v1/tenants/{tenantID}/ip-rules/config",
		"PUT /v1/tenants/{tenantID}/rate-limits",
		"DELETE /v1/tenants/{tenantID}/rate-limits",
		"PUT /v1/users/{id}/mfa-required",
		"DELETE /v1/users/{id}/mfa",
		"POST /v1/users/{id}/password",

		// Single sign-on, directories and the domains that route to them.
		"POST /v1/tenants/{tenantID}/saml",
		"PATCH /v1/tenants/{tenantID}/saml/{id}",
		"DELETE /v1/tenants/{tenantID}/saml/{id}",
		"POST /v1/tenants/{tenantID}/saml-providers",
		"PATCH /v1/tenants/{tenantID}/saml-providers/{id}",
		"DELETE /v1/tenants/{tenantID}/saml-providers/{id}",
		"POST /v1/tenants/{tenantID}/ldap",
		"PATCH /v1/tenants/{tenantID}/ldap/{id}",
		"DELETE /v1/tenants/{tenantID}/ldap/{id}",
		"POST /v1/social/providers",
		"PATCH /v1/social/providers/{provider}",
		"DELETE /v1/social/providers/{provider}",
		"POST /v1/tenants/{tenantID}/domains",
		"PATCH /v1/tenants/{tenantID}/domains/{id}",
		"DELETE /v1/tenants/{tenantID}/domains/{id}",
		"POST /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings",
		"PUT /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}",
		"DELETE /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}",
		"POST /v1/tenants/{tenantID}/admin-portal/links",
		"DELETE /v1/tenants/{tenantID}/admin-portal/links/{id}",

		// Email the organisation sends in its name.
		"PUT /v1/tenants/{tenantID}/email-templates/{key}",
		"DELETE /v1/tenants/{tenantID}/email-templates/{key}",

		// Retention and audit streaming.
		"PUT /v1/tenants/{tenantID}/retention",
		"POST /v1/tenants/{tenantID}/retention/run",
		"PUT /v1/tenants/{tenantID}/audit/anomaly-settings",
		"POST /v1/tenants/{tenantID}/log-sinks",
		"PATCH /v1/tenants/{tenantID}/log-sinks/{id}",
		"DELETE /v1/tenants/{tenantID}/log-sinks/{id}",

		// Handing out authority: what a role can do, who holds it, who is invited
		// to hold it, and the relationship and attribute rules that decide access.
		"POST /v1/roles/{roleID}/permissions/{permID}",
		"DELETE /v1/roles/{roleID}/permissions/{permID}",
		"POST /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}",
		"DELETE /v1/users/{userID}/tenants/{tenantID}/roles/{roleID}",
		"POST /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}",
		"DELETE /v1/tenants/{tenantID}/groups/{groupID}/roles/{roleID}",
		"POST /v1/invites",
		"POST /v1/tenants/{tenantID}/relation-tuples",
		"DELETE /v1/tenants/{tenantID}/relation-tuples/{id}",
		"POST /v1/tenants/{tenantID}/abac/policies",
		"PATCH /v1/tenants/{tenantID}/abac/policies/{id}",
		"DELETE /v1/tenants/{tenantID}/abac/policies/{id}",

		// Bringing an account back.
		"POST /v1/users/{id}/reactivate",
		"POST /v1/users/{id}/restore",

		// Destroying an organisation or an account. Updating the organisation
		// can suspend it, which locks every member out.
		"DELETE /v1/tenants/{tenantID}",
		"PATCH /v1/tenants/{tenantID}",
		"DELETE /v1/users/{id}",
		"DELETE /v1/users/{id}/membership",
		"DELETE /v1/users/{id}/purge",
		"POST /v1/gdpr/purge",
	} {
		routes[route] = mfa.StepUpAlways
	}
	return routes
}
