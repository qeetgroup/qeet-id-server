package bootstrap

import (
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/developer/agent"
	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey"
	"github.com/qeetgroup/qeet-id-server/internal/developer/authhook"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secret"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
)

// developerServices are the developer context's: machine credentials (API
// keys, service principals, AI agents), sign-in hooks, webhooks, the secrets
// and token vaults and verifiable credentials.
type developerServices struct {
	apikeyService    *apikey.Service
	principalService *principal.Service
	authHookService  *authhook.Service
	agentService     *agent.Service // AI-agent identities (ephemeral scoped tokens)
	vcService        *vc.Service    // W3C verifiable credentials (JWT-VC)
	webhookService   *webhook.Service
	secretService    *secret.Service
	// Token Vault seals with the same cipher as the secrets vault: one
	// KMS/static-key setup backs both encrypted stores.
	tokenVaultService *tokenvault.Service
}

// newDeveloper builds the developer context's services.
func (w *wiring) newDeveloper() *developerServices {
	return &developerServices{
		apikeyService:     apikey.NewService(w.pool),
		principalService:  principal.NewService(w.pool, w.issuer),
		authHookService:   authhook.NewService(w.pool, w.outboundPolicy),
		agentService:      agent.NewService(w.pool, w.issuer),
		vcService:         vc.NewService(w.pool, w.issuer),
		webhookService:    webhook.NewService(w.pool, w.outboundPolicy),
		secretService:     secret.NewService(w.pool, w.sharedCipher),
		tokenVaultService: tokenvault.NewService(w.pool, w.sharedCipher, w.outboundPolicy),
	}
}

// wireDeveloper connects the developer context's services to the rest.
func (w *wiring) wireDeveloper() {
	w.authHookService.SetCipher(w.sharedCipher)
	w.webhookService.SetCipher(w.sharedCipher)
	w.webhookService.SetNotifier(w.notificationService) // alert webhook managers when a failing endpoint is turned off
	w.webhookService.SetPlanGate(w.entitlementSvc)      // webhooks (feature)
	w.apikeyService.SetPlanLimiter(w.entitlementSvc)    // api_keys
}

// developerHandlers serves the developer context.
func (w *wiring) developerHandlers(d *Deps) {
	cfg := w.cfg
	d.APIKey = &apikey.Handler{Service: w.apikeyService, GrantCheck: w.rbacRepo.CheckGrantScopes}
	d.APIKeyService = w.apikeyService
	d.Principal = &principal.Handler{Service: w.principalService, GrantCheck: w.rbacRepo.CheckGrantScopes}
	d.Webhook = &webhook.Handler{Service: w.webhookService}
	d.Secret = &secret.Handler{Service: w.secretService}
	d.TokenVault = &tokenvault.Handler{Service: w.tokenVaultService, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev()}
	d.AuthHook = &authhook.Handler{Service: w.authHookService}
	d.Agent = &agent.Handler{Service: w.agentService, GrantCheck: w.rbacRepo.CheckGrantScopes}
	d.VC = &vc.Handler{Service: w.vcService}
}

// developerPolicies are the developer context's routes whose policy is
// neither a permission nor user-only. These derive a vault:<resource> scope
// from the path and enforce it in the handler; the central catalogue still
// classifies the actor surface.
func developerPolicies() map[string]rbac.RoutePolicy {
	return map[string]rbac.RoutePolicy{
		"GET /v1/vault/{name}":                         rbac.HandlerAuthorizedPolicy(true, "vault:read"),
		"GET /v1/vault/tokens/{provider}/access-token": rbac.HandlerAuthorizedPolicy(true, "vault:read"),
	}
}

// developerPermissions are the developer context's routes and the user permission
// each needs, as userPermissionMap lists them.
func developerPermissions() map[string]string {
	return map[string]string{
		// API keys + service principals (M2M).
		"POST /v1/api-keys": "apikey.write",
		"GET /v1/organizations/{organizationID}/api-keys":                               "apikey.read",
		"DELETE /v1/api-keys/{id}":                                                      "apikey.write",
		"POST /v1/service-principals":                                                   "apikey.write",
		"GET /v1/organizations/{organizationID}/service-principals":                     "apikey.read",
		"DELETE /v1/service-principals/{id}":                                            "apikey.write",
		"POST /v1/organizations/{organizationID}/api-keys/{id}/rotate":                  "apikey.write",
		"POST /v1/organizations/{organizationID}/service-principals/{id}/rotate-secret": "apikey.write",
		"POST /v1/organizations/{organizationID}/service-principals/{id}/enable":        "apikey.write",

		// Webhooks.
		"GET /v1/organizations/{organizationID}/webhooks":                                       "webhook.read",
		"GET /v1/organizations/{organizationID}/webhooks/events":                                "webhook.read",
		"POST /v1/organizations/{organizationID}/webhooks/{id}/enable":                          "webhook.write",
		"POST /v1/organizations/{organizationID}/webhooks/{id}/rotate-secret":                   "webhook.write",
		"PATCH /v1/organizations/{organizationID}/webhooks/{id}":                                "webhook.write",
		"POST /v1/organizations/{organizationID}/webhooks/{id}/deliveries/retry":                "webhook.write",
		"GET /v1/organizations/{organizationID}/webhooks/{id}/deliveries/{deliveryID}/attempts": "webhook.read",
		"GET /v1/webhooks/{id}":                                "webhook.read",
		"GET /v1/webhooks/{id}/deliveries":                     "webhook.read",
		"POST /v1/webhooks":                                    "webhook.write",
		"DELETE /v1/webhooks/{id}":                             "webhook.write",
		"POST /v1/webhooks/{id}/test":                          "webhook.write",
		"POST /v1/webhooks/{id}/deliveries/{deliveryID}/retry": "webhook.write",

		// Secrets vault.
		"GET /v1/organizations/{organizationID}/secrets":              "secret.read",
		"POST /v1/organizations/{organizationID}/secrets":             "secret.write",
		"PATCH /v1/organizations/{organizationID}/secrets/{id}":       "secret.write",
		"DELETE /v1/organizations/{organizationID}/secrets/{id}":      "secret.write",
		"POST /v1/organizations/{organizationID}/secrets/{id}/reveal": "secret.read",

		// Third-party token-vault provider administration.
		"GET /v1/organizations/{organizationID}/vault/tokens/providers":               "secret.read",
		"POST /v1/organizations/{organizationID}/vault/tokens/providers":              "secret.write",
		"DELETE /v1/organizations/{organizationID}/vault/tokens/providers/{provider}": "secret.write",

		// Verifiable credentials.
		"GET /v1/organizations/{organizationID}/credentials":              "secret.read",
		"POST /v1/organizations/{organizationID}/credentials":             "secret.write",
		"POST /v1/organizations/{organizationID}/credentials/{id}/revoke": "secret.write",

		// Agent identities share the existing non-human identity permissions.
		"GET /v1/organizations/{organizationID}/agents":                                 "apikey.read",
		"POST /v1/organizations/{organizationID}/agents":                                "apikey.write",
		"POST /v1/organizations/{organizationID}/agents/kill-all":                       "apikey.write",
		"POST /v1/organizations/{organizationID}/agents/resume-all":                     "apikey.write",
		"POST /v1/organizations/{organizationID}/agents/{id}/rotate-secret":             "apikey.write",
		"DELETE /v1/organizations/{organizationID}/agents/{id}":                         "apikey.write",
		"PATCH /v1/organizations/{organizationID}/agents/{id}":                          "apikey.write",
		"POST /v1/organizations/{organizationID}/agents/{id}/suspend":                   "apikey.write",
		"POST /v1/organizations/{organizationID}/agents/{id}/resume":                    "apikey.write",
		"POST /v1/organizations/{organizationID}/agents/{id}/decommission":              "apikey.write",
		"GET /v1/organizations/{organizationID}/agents/sponsored-by/{userID}":           "apikey.read",
		"POST /v1/organizations/{organizationID}/agents/sponsored-by/{userID}/transfer": "apikey.write",

		// Synchronous login hooks are organization security policy.
		"GET /v1/organizations/{organizationID}/auth-hooks":            "policy.read",
		"POST /v1/organizations/{organizationID}/auth-hooks":           "policy.write",
		"PATCH /v1/organizations/{organizationID}/auth-hooks/{id}":     "policy.write",
		"POST /v1/organizations/{organizationID}/auth-hooks/{id}/test": "policy.write",
		"DELETE /v1/organizations/{organizationID}/auth-hooks/{id}":    "policy.write",
	}
}

// developerUserOnlyRoutes are the developer context's routes of a person's own account or
// resources, which RoutePolicies makes user-only.
func developerUserOnlyRoutes() []string {
	return []string{
		"GET /v1/vault/tokens",
		"GET /v1/vault/tokens/{provider}/connect",
		"DELETE /v1/vault/tokens/{provider}",
	}
}

// developerStepUps are the developer context's routes that need a recent step-up, as
// StepUpRoutes lists them.
func developerStepUps() map[string]mfa.StepUpRule {
	return stepUps(
		nil,
		[]string{
			// Machine credentials.
			"POST /v1/api-keys",
			"DELETE /v1/api-keys/{id}",
			"POST /v1/service-principals",
			"DELETE /v1/service-principals/{id}",
			"POST /v1/organizations/{organizationID}/api-keys/{id}/rotate",
			"POST /v1/organizations/{organizationID}/service-principals/{id}/rotate-secret",
			"POST /v1/organizations/{organizationID}/service-principals/{id}/enable",
			"POST /v1/organizations/{organizationID}/agents/resume-all",
			"POST /v1/organizations/{organizationID}/agents/{id}/rotate-secret",
			"POST /v1/organizations/{organizationID}/agents",
			"PATCH /v1/organizations/{organizationID}/agents/{id}",
			"DELETE /v1/organizations/{organizationID}/agents/{id}",
			"POST /v1/organizations/{organizationID}/agents/{id}/resume",
			"POST /v1/organizations/{organizationID}/agents/sponsored-by/{userID}/transfer",
			"POST /v1/organizations/{organizationID}/credentials",
			"POST /v1/organizations/{organizationID}/credentials/{id}/revoke",
			"POST /v1/webhooks",
			"DELETE /v1/webhooks/{id}",
			"POST /v1/organizations/{organizationID}/webhooks/{id}/enable",
			"POST /v1/organizations/{organizationID}/webhooks/{id}/rotate-secret",
			"PATCH /v1/organizations/{organizationID}/webhooks/{id}",
			"POST /v1/organizations/{organizationID}/auth-hooks",
			"PATCH /v1/organizations/{organizationID}/auth-hooks/{id}",
			"DELETE /v1/organizations/{organizationID}/auth-hooks/{id}",

			// Secrets and keys.
			"POST /v1/organizations/{organizationID}/secrets",
			"PATCH /v1/organizations/{organizationID}/secrets/{id}",
			"DELETE /v1/organizations/{organizationID}/secrets/{id}",
			"POST /v1/organizations/{organizationID}/secrets/{id}/reveal",
			"POST /v1/organizations/{organizationID}/vault/tokens/providers",
			"DELETE /v1/organizations/{organizationID}/vault/tokens/providers/{provider}",
		},
	)
}
