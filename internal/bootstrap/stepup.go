package bootstrap

import "github.com/qeetgroup/qeet-id-server/internal/access/mfa"

// stepUpRoutes is the catalogue of authenticated routes that need a step-up
// of the calling session, consumed by mfa.Service.StepUpGate. A stolen access
// token alone must not be able to add or remove a factor, mint or revoke a
// machine credential, read or change a secret, weaken sign-in or security
// policy, reconfigure single sign-on, change retention or audit streaming, or
// destroy an account or organisation.
//
// StepUpWhenFactorHeld covers a person's own factors and sign-in methods: a
// first factor can be set up with nothing to step up with. Everything else is
// StepUpAlways, which machine principals (API keys, service principals,
// agents) can never meet, as they hold no session.
//
// Keys MUST match the composed route pattern ("/v1" included).
// TestSensitiveRoutesNeedStepUp fails when a route that looks sensitive is
// neither listed here nor in stepUpExempt.
func stepUpRoutes() map[string]mfa.StepUpRule {
	routes := map[string]mfa.StepUpRule{}
	for _, route := range []string{
		// The person's own factors and sign-in methods.
		"POST /v1/mfa/totp/enroll/start",
		"POST /v1/mfa/otp/factors",
		"DELETE /v1/mfa/otp/factors/{id}",
		"POST /v1/mfa/push/devices",
		"DELETE /v1/mfa/push/devices/{id}",
		"POST /v1/passkeys/register/begin",
		"DELETE /v1/passkeys/{id}",
		"POST /v1/social/{provider}/link/start",
		"POST /v1/account/delete",
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

		// Destroying an organisation or an account. Updating the organisation
		// can suspend it, which locks every member out.
		"DELETE /v1/tenants/{tenantID}",
		"PATCH /v1/tenants/{tenantID}",
		"DELETE /v1/users/{id}",
		"DELETE /v1/users/{id}/purge",
		"POST /v1/gdpr/purge",
	} {
		routes[route] = mfa.StepUpAlways
	}
	return routes
}

// stepUpExempt lists the routes that look sensitive by path but deliberately
// need no step-up, each with the reason. TestSensitiveRoutesNeedStepUp reads
// it so a new sensitive-looking route has to be classified one way or the
// other.
func stepUpExempt() map[string]string {
	return map[string]string{
		"POST /v1/mfa/totp/enroll/confirm":                                                  "completes a setup its start already gated, with a code from the app",
		"POST /v1/mfa/totp/verify":                                                          "is how a session steps up",
		"POST /v1/mfa/otp/verify":                                                           "is how a session steps up",
		"POST /v1/mfa/otp/factors/{id}/confirm":                                             "completes a setup its start already gated, with a code sent to it",
		"POST /v1/mfa/otp/factors/{id}/challenge":                                           "sends a step-up code",
		"POST /v1/mfa/webauthn/challenge":                                                   "is how a session steps up",
		"POST /v1/mfa/webauthn/verify":                                                      "is how a session steps up",
		"POST /v1/passkeys/register/finish":                                                 "completes a ceremony its begin already gated",
		"PATCH /v1/passkeys/{id}":                                                           "renames a passkey",
		"DELETE /v1/me/social/identities/{id}":                                              "removes a way in; adding one is gated",
		"DELETE /v1/social/identities/{id}":                                                 "removes a way in; adding one is gated",
		"PATCH /v1/users/{id}":                                                              "edits profile fields; suspending must stay instant in an incident",
		"POST /v1/tenants/{tenantID}/agents/kill-all":                                       "stops agents; must stay instant in an incident",
		"POST /v1/tenants/{tenantID}/agents/{id}/suspend":                                   "stops an agent; must stay instant in an incident",
		"POST /v1/tenants/{tenantID}/agents/{id}/decommission":                              "stops an agent for good; must stay instant in an incident",
		"POST /v1/tenants/{tenantID}/oidc/clients/{id}/review":                              "records a review decision without changing the client",
		"POST /v1/tenants/{tenantID}/ip-rules/check":                                        "evaluates an address against the rules",
		"POST /v1/tenants/{tenantID}/retention/preview":                                     "reports what a run would remove",
		"POST /v1/tenants/{tenantID}/saml/{id}/test":                                        "tests a connection",
		"POST /v1/tenants/{tenantID}/ldap/{id}/test":                                        "tests a connection",
		"POST /v1/tenants/{tenantID}/domains/{id}/verify":                                   "checks DNS proof the organisation already published",
		"POST /v1/tenants/{tenantID}/directory/connections/{connectionID}/mappings/preview": "previews a mapping",
		"POST /v1/tenants/{tenantID}/email-templates/{key}/preview":                         "renders a template",
		"POST /v1/tenants/{tenantID}/email-templates/{key}/test":                            "sends a template to the caller",
		"POST /v1/qeetai/provider-config/test":                                              "tests the saved configuration",
		"POST /v1/webhooks/{id}/test":                                                       "sends a test event to the endpoint already configured",
		"POST /v1/webhooks/{id}/deliveries/{deliveryID}/retry":                              "redelivers an event already sent",
		"POST /v1/auth/sessions/revoke-all":                                                 "ends sessions; must stay instant in an incident",
		"POST /v1/auth/sessions/revoke-others":                                              "ends sessions; must stay instant in an incident",
		"DELETE /v1/auth/sessions/{id}":                                                     "ends a session; must stay instant in an incident",
		"POST /v1/users/{id}/sessions/revoke-all":                                           "ends sessions; must stay instant in an incident",
		"POST /v1/auth/password":                                                            "needs the current password",
		"POST /v1/account/export":                                                           "exports the caller's own data to the caller",
		"POST /v1/gdpr/export":                                                              "exports a person's data for a subject-access request",
		"DELETE /v1/gdpr/purge/{id}":                                                        "cancels a scheduled purge",
		"DELETE /v1/vault/tokens/{provider}":                                                "removes the caller's own stored token",
		"DELETE /v1/tenants/{tenantID}/oauth/grants/{id}":                                   "revokes an application's access",
		"DELETE /v1/tenants/{tenantID}/oauth/devices/{id}":                                  "revokes a device's access",
		"POST /v1/tenants/{tenantID}/audit/anomalies/{id}/resolve":                          "records a triage decision",
		"POST /v1/tenants/{tenantID}/security/anomalies/{id}/resolve":                       "records a triage decision",
	}
}
