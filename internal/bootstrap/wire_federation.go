package bootstrap

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/directory"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// federationServices are the federation context's: Qeet ID as an OpenID
// Connect provider and SAML identity provider, and the organizations' social,
// SAML, OpenID Connect, SCIM and LDAP connections.
type federationServices struct {
	oidcService        *oidc.Service
	socialService      *social.Service
	scimService        *scim.Service
	samlService        *saml.Service
	oidcSSOService     *oidcsso.Service
	samlIdP            *saml.IdP
	adminPortalService *adminportal.Service
	ldapService        *ldap.Service
	directoryService   *directory.Service
}

// newFederation builds the federation context's services.
func (w *wiring) newFederation() *federationServices {
	f := &federationServices{
		oidcService:        oidc.NewService(w.pool, w.issuer),
		socialService:      social.NewService(w.pool, w.authService, w.cfg.AppBaseURL, w.outboundPolicy),
		scimService:        scim.NewService(w.pool, w.userRepo),
		samlService:        saml.NewService(w.pool, w.authService, w.cfg.AppBaseURL),
		oidcSSOService:     oidcsso.NewService(w.pool, w.authService, w.cfg.AppBaseURL, w.outboundPolicy),
		samlIdP:            newSAMLIdP(w.pool, w.cfg, w.authService),
		adminPortalService: adminportal.NewService(w.pool, w.brandingRepo, w.cfg.LoginBaseURL),
		ldapService:        ldap.NewService(w.pool, w.authService, w.outboundPolicy),
	}
	f.directoryService = directory.NewService(f.scimService, f.ldapService)
	return f
}

// newSAMLIdP returns Qeet ID's SAML identity provider, exiting when its
// identity can't be loaded.
func newSAMLIdP(pool *pgxpool.Pool, cfg *config.Config, authService *auth.Service) *saml.IdP {
	samlIdPKeyPEM, samlIdPCertPEM := samlIdPIdentity(cfg)
	samlIdP, err := saml.NewIdP(pool, samlIdPKeyPEM, samlIdPCertPEM, cfg.LoginBaseURL, authService)
	if err != nil {
		slog.Error("init saml idp", "err", err)
		os.Exit(1)
	}
	return samlIdP
}

// wireFederation connects the federation context's services to the rest.
func (w *wiring) wireFederation() {
	w.wireOIDC()
	w.wireSocial()
	w.wireSSO()
	w.wireDirectories()
}

// wireOIDC connects Qeet ID as an OpenID Connect provider.
func (w *wiring) wireOIDC() {
	w.oidcService.SetAgentStatus(w.agentService.AgentStatus)         // a suspended agent's tokens introspect inactive
	w.oidcService.SetSessionLive(w.authService.SessionLive)          // an ended session's tokens introspect inactive and can't be exchanged
	w.oidcService.SetPrincipalLive(w.principalService.PrincipalLive) // a disabled service principal's tokens introspect inactive
	w.oidcService.SetGrantMaxAge(w.cfg.SessionMaxAge)                // grant bound where the organization sets none
	w.oidcService.SetNotifier(w.notificationService)                 // CIBA async consent prompts
	// A CIBA approval is a sign-in: the session it comes through meets the organization's second factor.
	w.oidcService.SetSessionFactors(w.authService.SessionFactorShortfall)
	// The client_credentials grant serves the service principals, then the agents.
	w.oidcService.SetMachineClients(w.principalService, w.agentService)
	w.oidcService.SetLogoutHTTPClient(w.outboundPolicy)
	w.oidcService.SetAddressPolicy(w.ipAllowService) // address rules: application authorize, device approval and collection
	w.oidcService.SetPlanLimiter(w.entitlementSvc)   // apps (relying parties)
}

// wireSocial connects social sign-in.
func (w *wiring) wireSocial() {
	cfg := w.cfg
	w.socialService.SetCipher(w.sharedCipher)
	// Allowlist for the hosted flow's return_to. The callback sets the SSO
	// cookie before redirecting, so an unvalidated value would be an open
	// redirect on the auth domain. AllowedOrigins is already the vetted browser
	// origin set (Validate() refuses a wildcard outside dev).
	w.socialService.SetAllowedReturnOrigins(
		append([]string{cfg.AppBaseURL, cfg.LoginBaseURL}, cfg.AllowedOrigins()...)...)
	setPlatformSocialProviders(w.socialService, cfg)
	w.socialService.SetDomainCapture(w.domainVerifyService) // social sign-up
}

// wireSSO connects single sign-on: Qeet ID's SAML identity provider and the
// organizations' SAML and OpenID Connect connections.
func (w *wiring) wireSSO() {
	cfg := w.cfg
	w.oidcSSOService.SetCipher(w.sharedCipher)
	w.samlService.SetEgressPolicy(w.outboundPolicy) // IdP metadata URLs
	w.samlService.SetCipher(w.sharedCipher)         // the connections' SP encryption keys
	// A SAML or OpenID Connect sign-in started on the hosted login returns there: the same return_to
	// allowlist as the hosted social sign-in's.
	ssoReturnOrigins := append([]string{cfg.AppBaseURL, cfg.LoginBaseURL}, cfg.AllowedOrigins()...)
	w.samlService.SetHostedLogin(cfg.LoginBaseURL, ssoReturnOrigins...)
	w.oidcSSOService.SetHostedLogin(cfg.LoginBaseURL, ssoReturnOrigins...)
	// The SAML IdP signs an assertion under the same address rules and second factor.
	w.samlIdP.SetSignInRules(w.ipAllowService, w.authService)
	w.samlIdP.SetPlanGate(w.entitlementSvc)        // SSO (SAML), as identity provider
	w.samlService.SetPlanGate(w.entitlementSvc)    // SSO (SAML), through an organization's identity provider
	w.oidcSSOService.SetPlanGate(w.entitlementSvc) // SSO (OpenID Connect connections)
}

// wireDirectories connects SCIM and LDAP and the directory view over both.
func (w *wiring) wireDirectories() {
	w.scimService.SetSessionSignals(w.sessionSignals)
	w.ldapService.SetCipher(w.sharedCipher)
	w.ldapService.SetAllowSkipTLSVerify(w.cfg.IsDev()) // skip_tls_verify is a dev-only escape hatch
	w.directoryService.SetEventStore(w.pool)
	w.scimService.SetOperationObserver(w.directoryService)
	w.ldapService.SetOperationObserver(w.directoryService)
	w.scimService.SetProfileMapper(w.directoryService)
	w.ldapService.SetProfileMapper(w.directoryService)
	w.scimService.SetSeatGuard(w.inviteService) // seats: the same, through a directory-managed group
	w.scimService.SetPlanGate(w.entitlementSvc) // SCIM
	w.ldapService.SetPlanGate(w.entitlementSvc) // LDAP
}

// federationHandlers serves the federation context.
func (w *wiring) federationHandlers(d *Deps) {
	cfg := w.cfg
	samlHandler := &saml.Handler{Service: w.samlService, IdP: w.samlIdP, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev(), ActOnCheck: w.rbacRepo.CheckActOn}
	d.OIDC = &oidc.Handler{Service: w.oidcService, Sessions: w.authService, Providers: w.socialService, Registration: w.authPolicyService, DeviceTrust: w.authPolicyService, Methods: w.authPolicyService, Policy: w.authPolicyService, Branding: w.brandingRepo, LoginBaseURL: cfg.LoginBaseURL, CookieSecure: !cfg.IsDev(), PublicBaseURL: cfg.PublicBaseURL}
	d.Social = &social.Handler{Service: w.socialService, CookieSecure: !cfg.IsDev(), LoginBaseURL: cfg.LoginBaseURL, PublicBaseURL: cfg.PublicBaseURL, ActOnCheck: w.rbacRepo.CheckActOn}
	d.SCIM = &scim.Handler{Service: w.scimService, PublicBaseURL: cfg.PublicBaseURL}
	d.SAML = samlHandler
	d.AdminPortal = &adminportal.Handler{Service: w.adminPortalService, SAML: w.samlService, SAMLSignIn: samlHandler, SCIM: w.scimService, Domains: w.domainVerifyService, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev()}
	d.LDAP = &ldap.Handler{Service: w.ldapService, CookieSecure: !cfg.IsDev(), ActOnCheck: w.rbacRepo.CheckActOn}
	d.SSOGroups = &ssosync.Handler{Service: ssosync.NewService(w.pool), GrantCheck: w.rbacRepo.CheckGrantGroup}
	d.OIDCSSO = &oidcsso.Handler{Service: w.oidcSSOService, PublicBaseURL: cfg.PublicBaseURL, CookieSecure: !cfg.IsDev(), ActOnCheck: w.rbacRepo.CheckActOn}
	d.Directory = &directory.Handler{Service: w.directoryService}
}

// federationPolicies are the federation context's routes whose policy is
// neither a permission nor user-only: userinfo is the one route made for
// applications (ApplicationTokenRoutes), and OpenID Connect needs openid of a
// token reading it.
func federationPolicies() map[string]rbac.RoutePolicy {
	return map[string]rbac.RoutePolicy{
		"GET /v1/oauth/userinfo":  rbac.UserOnlyPolicy("openid"),
		"POST /v1/oauth/userinfo": rbac.UserOnlyPolicy("openid"),
	}
}

// samlMetadataRefreshJob refreshes each SAML connection backed by its IdP's
// metadata URL, so it picks up the IdP's new signing certificates. outbound,
// public addresses only if not given, bounds the fetches.
func samlMetadataRefreshJob(pool *pgxpool.Pool, outbound []*egress.Policy) worker.Scheduled {
	return worker.Scheduled{
		Name:     "saml-metadata-refresh",
		Interval: saml.MetadataRefreshInterval,
		Run: func(ctx context.Context) error {
			run, err := saml.RefreshMetadata(ctx, pool, egress.PublicPolicy(outbound...))
			if run.Refreshed+run.Failed > 0 {
				slog.Info("saml metadata refreshed", "refreshed", run.Refreshed, "failed", run.Failed)
			}
			return err
		},
	}
}

// samlTestSignInCleanupJob removes SAML test sign-ins past their retention: a
// test sign-in holds what the IdP asserted about a person.
func samlTestSignInCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "saml-test-sign-in-cleanup",
		Interval: 15 * time.Minute,
		Run: func(ctx context.Context) error {
			n, err := saml.PurgeTestSignIns(ctx, pool, saml.TestSignInRetention)
			if err != nil {
				return err
			}
			slog.Info("SAML test sign-ins cleaned", "deleted", n)
			return nil
		},
	}
}

// federationPermissions are the federation context's routes and the user permission
// each needs, as userPermissionMap lists them.
func federationPermissions() map[string]string {
	return map[string]string{
		// SSO / identity connections: OIDC clients + grants/devices.
		"GET /v1/oidc/signing-keys":                                               "connection.read",
		"POST /v1/oidc/clients":                                                   "connection.write",
		"DELETE /v1/oidc/clients/{id}":                                            "connection.write",
		"GET /v1/organizations/{organizationID}/oidc/clients":                     "connection.read",
		"POST /v1/organizations/{organizationID}/oidc/clients":                    "connection.write",
		"GET /v1/organizations/{organizationID}/oidc/clients/{id}":                "connection.read",
		"PATCH /v1/organizations/{organizationID}/oidc/clients/{id}":              "connection.write",
		"GET /v1/organizations/{organizationID}/oidc/clients/{id}/auth-failures":  "connection.read",
		"GET /v1/organizations/{organizationID}/oidc/resources":                   "connection.read",
		"POST /v1/organizations/{organizationID}/oidc/resources":                  "connection.write",
		"DELETE /v1/organizations/{organizationID}/oidc/resources/{id}":           "connection.write",
		"DELETE /v1/organizations/{organizationID}/oidc/clients/{id}":             "connection.write",
		"POST /v1/organizations/{organizationID}/oidc/clients/{id}/rotate-secret": "connection.write",
		"GET /v1/organizations/{organizationID}/oidc/clients/shadow-ai":           "connection.read",
		"POST /v1/organizations/{organizationID}/oidc/clients/{id}/review":        "connection.write",
		"GET /v1/organizations/{organizationID}/oauth/grants":                     "connection.read",
		"DELETE /v1/organizations/{organizationID}/oauth/grants/{id}":             "connection.write",
		"POST /v1/organizations/{organizationID}/oauth/grants/revoke":             "connection.write",
		"GET /v1/organizations/{organizationID}/oauth/devices":                    "connection.read",
		"DELETE /v1/organizations/{organizationID}/oauth/devices/{id}":            "connection.write",

		// SSO connections: SAML / OIDC / SCIM / LDAP / social provider config.
		"GET /v1/organizations/{organizationID}/saml":                                                         "connection.read",
		"POST /v1/organizations/{organizationID}/saml":                                                        "connection.write",
		"GET /v1/organizations/{organizationID}/saml/{id}":                                                    "connection.read",
		"PATCH /v1/organizations/{organizationID}/saml/{id}":                                                  "connection.write",
		"POST /v1/organizations/{organizationID}/saml/{id}/test":                                              "connection.write",
		"DELETE /v1/organizations/{organizationID}/saml/{id}":                                                 "connection.write",
		"GET /v1/organizations/{organizationID}/saml/{id}/group-mappings":                                     "connection.read",
		"POST /v1/organizations/{organizationID}/saml/{id}/group-mappings":                                    "group.write", // decides who sign-ins put in a group
		"DELETE /v1/organizations/{organizationID}/saml/{id}/group-mappings/{mappingID}":                      "group.write",
		"GET /v1/organizations/{organizationID}/ldap/{id}/group-mappings":                                     "connection.read",
		"POST /v1/organizations/{organizationID}/ldap/{id}/group-mappings":                                    "group.write", // decides who sign-ins put in a group
		"DELETE /v1/organizations/{organizationID}/ldap/{id}/group-mappings/{mappingID}":                      "group.write",
		"POST /v1/organizations/{organizationID}/saml/import":                                                 "connection.write",
		"POST /v1/organizations/{organizationID}/saml/{id}/metadata":                                          "connection.write",
		"POST /v1/organizations/{organizationID}/saml/{id}/certificates":                                      "connection.write",
		"DELETE /v1/organizations/{organizationID}/saml/{id}/certificates/{certificateID}":                    "connection.write",
		"GET /v1/organizations/{organizationID}/saml-providers":                                               "connection.read",
		"POST /v1/organizations/{organizationID}/saml-providers":                                              "connection.write",
		"GET /v1/organizations/{organizationID}/saml-providers/{id}":                                          "connection.read",
		"PATCH /v1/organizations/{organizationID}/saml-providers/{id}":                                        "connection.write",
		"DELETE /v1/organizations/{organizationID}/saml-providers/{id}":                                       "connection.write",
		"GET /v1/organizations/{organizationID}/saml-providers/{id}/assignments":                              "connection.read",
		"POST /v1/organizations/{organizationID}/saml-providers/{id}/assignments/users/{userID}":              "connection.write",
		"DELETE /v1/organizations/{organizationID}/saml-providers/{id}/assignments/users/{userID}":            "connection.write",
		"POST /v1/organizations/{organizationID}/saml-providers/{id}/assignments/groups/{groupID}":            "connection.write",
		"DELETE /v1/organizations/{organizationID}/saml-providers/{id}/assignments/groups/{groupID}":          "connection.write",
		"GET /v1/organizations/{organizationID}/scim":                                                         "connection.read",
		"GET /v1/organizations/{organizationID}/directory/connections":                                        "connection.read",
		"GET /v1/organizations/{organizationID}/directory/profiles/{userID}":                                  "user.read",
		"GET /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings":                "connection.read",
		"POST /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings":               "connection.write",
		"POST /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings/preview":       "connection.read",
		"PUT /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings/{mappingID}":    "connection.write",
		"DELETE /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings/{mappingID}": "connection.write",
		"GET /v1/organizations/{organizationID}/directory/errors":                                             "connection.read",
		"POST /v1/organizations/{organizationID}/directory/errors/{eventID}/resolve":                          "connection.write",
		"POST /v1/organizations/{organizationID}/directory/errors/{eventID}/retry":                            "connection.write",
		"GET /v1/organizations/{organizationID}/directory/activity":                                           "connection.read",
		"POST /v1/organizations/{organizationID}/directory/alerts":                                            "connection.write",
		"GET /v1/organizations/{organizationID}/directory/alerts":                                             "connection.read",
		"PATCH /v1/organizations/{organizationID}/directory/alerts/{alertID}":                                 "connection.write",
		"DELETE /v1/organizations/{organizationID}/directory/alerts/{alertID}":                                "connection.write",
		"POST /v1/organizations/{organizationID}/scim/token":                                                  "connection.write",
		"DELETE /v1/organizations/{organizationID}/scim/token":                                                "connection.write",
		"GET /v1/organizations/{organizationID}/scim/tokens":                                                  "connection.read",
		"POST /v1/organizations/{organizationID}/scim/tokens":                                                 "connection.write",
		"POST /v1/organizations/{organizationID}/scim/tokens/{id}/rotate":                                     "connection.write",
		"DELETE /v1/organizations/{organizationID}/scim/tokens/{id}":                                          "connection.write",
		"GET /v1/organizations/{organizationID}/scim/users":                                                   "connection.read",
		"GET /v1/organizations/{organizationID}/scim/groups":                                                  "connection.read",
		"POST /v1/organizations/{organizationID}/admin-portal/links":                                          "connection.write",
		"GET /v1/organizations/{organizationID}/admin-portal/links":                                           "connection.read",
		"DELETE /v1/organizations/{organizationID}/admin-portal/links/{id}":                                   "connection.write",
		"GET /v1/organizations/{organizationID}/ldap":                                                         "connection.read",
		"POST /v1/organizations/{organizationID}/ldap":                                                        "connection.write",
		"GET /v1/organizations/{organizationID}/ldap/{id}":                                                    "connection.read",
		"PATCH /v1/organizations/{organizationID}/ldap/{id}":                                                  "connection.write",
		"DELETE /v1/organizations/{organizationID}/ldap/{id}":                                                 "connection.write",
		"POST /v1/organizations/{organizationID}/ldap/{id}/test":                                              "connection.write",
		"GET /v1/organizations/{organizationID}/oidc-connections":                                             "connection.read",
		"POST /v1/organizations/{organizationID}/oidc-connections":                                            "connection.write",
		"GET /v1/organizations/{organizationID}/oidc-connections/{id}":                                        "connection.read",
		"PATCH /v1/organizations/{organizationID}/oidc-connections/{id}":                                      "connection.write",
		"DELETE /v1/organizations/{organizationID}/oidc-connections/{id}":                                     "connection.write",
		"GET /v1/organizations/{organizationID}/social/providers":                                             "connection.read",
		"POST /v1/social/providers":                                                                           "connection.write",
		"PATCH /v1/social/providers/{provider}":                                                               "connection.write",
		"DELETE /v1/social/providers/{provider}":                                                              "connection.write",
		"GET /v1/users/{userID}/social/identities":                                                            "user.read",
		"DELETE /v1/social/identities/{id}":                                                                   "user.write",
	}
}

// federationUserOnlyRoutes are the federation context's routes of a person's own account or
// resources, which RoutePolicies makes user-only.
func federationUserOnlyRoutes() []string {
	return []string{
		"GET /v1/oauth/userinfo",
		"POST /v1/oauth/userinfo",
		"GET /v1/oauth/bc-authorize/pending",
		"POST /v1/oauth/bc-authorize/decision",
		"GET /v1/me/social/identities",
		"DELETE /v1/me/social/identities/{id}",
		"POST /v1/social/{provider}/link/start",
		"POST /v1/social/link/complete",
	}
}

// federationStepUps are the federation context's routes that need a recent step-up, as
// StepUpRoutes lists them.
func federationStepUps() map[string]mfa.StepUpRule {
	return stepUps(
		[]string{
			// Linking a social sign-in to the person's account.
			"POST /v1/social/{provider}/link/start",
		},
		[]string{
			// Machine credentials: applications and directory tokens.
			"POST /v1/oidc/clients",
			"DELETE /v1/oidc/clients/{id}",
			"POST /v1/organizations/{organizationID}/oidc/clients",
			"PATCH /v1/organizations/{organizationID}/oidc/clients/{id}",
			"DELETE /v1/organizations/{organizationID}/oidc/clients/{id}",
			"POST /v1/organizations/{organizationID}/oidc/clients/{id}/rotate-secret",
			"POST /v1/organizations/{organizationID}/scim/token",
			"DELETE /v1/organizations/{organizationID}/scim/token",
			"POST /v1/organizations/{organizationID}/scim/tokens",
			"POST /v1/organizations/{organizationID}/scim/tokens/{id}/rotate",
			"DELETE /v1/organizations/{organizationID}/scim/tokens/{id}",

			// Single sign-on, directories and the domains that route to them.
			"POST /v1/organizations/{organizationID}/saml",
			"PATCH /v1/organizations/{organizationID}/saml/{id}",
			"DELETE /v1/organizations/{organizationID}/saml/{id}",
			"POST /v1/organizations/{organizationID}/saml/import",
			"POST /v1/organizations/{organizationID}/saml/{id}/metadata",
			"POST /v1/organizations/{organizationID}/saml/{id}/certificates",
			"DELETE /v1/organizations/{organizationID}/saml/{id}/certificates/{certificateID}",
			"POST /v1/organizations/{organizationID}/saml-providers",
			"PATCH /v1/organizations/{organizationID}/saml-providers/{id}",
			"DELETE /v1/organizations/{organizationID}/saml-providers/{id}",
			"POST /v1/organizations/{organizationID}/saml-providers/{id}/assignments/users/{userID}",
			"DELETE /v1/organizations/{organizationID}/saml-providers/{id}/assignments/users/{userID}",
			"POST /v1/organizations/{organizationID}/saml-providers/{id}/assignments/groups/{groupID}",
			"DELETE /v1/organizations/{organizationID}/saml-providers/{id}/assignments/groups/{groupID}",
			"POST /v1/organizations/{organizationID}/ldap",
			"PATCH /v1/organizations/{organizationID}/ldap/{id}",
			"DELETE /v1/organizations/{organizationID}/ldap/{id}",
			"POST /v1/organizations/{organizationID}/saml/{id}/group-mappings",
			"DELETE /v1/organizations/{organizationID}/saml/{id}/group-mappings/{mappingID}",
			"POST /v1/organizations/{organizationID}/ldap/{id}/group-mappings",
			"DELETE /v1/organizations/{organizationID}/ldap/{id}/group-mappings/{mappingID}",
			"POST /v1/organizations/{organizationID}/oidc-connections",
			"PATCH /v1/organizations/{organizationID}/oidc-connections/{id}",
			"DELETE /v1/organizations/{organizationID}/oidc-connections/{id}",
			"POST /v1/social/providers",
			"PATCH /v1/social/providers/{provider}",
			"DELETE /v1/social/providers/{provider}",
			"POST /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings",
			"PUT /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings/{mappingID}",
			"DELETE /v1/organizations/{organizationID}/directory/connections/{connectionID}/mappings/{mappingID}",
			"POST /v1/organizations/{organizationID}/admin-portal/links",
			"DELETE /v1/organizations/{organizationID}/admin-portal/links/{id}",
		},
	)
}
