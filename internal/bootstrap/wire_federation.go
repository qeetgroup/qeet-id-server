package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

// newFederation builds the federation context's services, or says which one
// can't be built and why.
func (w *wiring) newFederation() (*federationServices, error) {
	f := &federationServices{adminPortalService: adminportal.NewService(w.pool, w.brandingRepo, w.cfg.LoginBaseURL)}
	for _, build := range []func(*federationServices) error{w.newOIDCProvider, w.newSocialSignIn, w.newSSO, w.newDirectorySync} {
		if err := build(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// newOIDCProvider builds Qeet ID as an OpenID Connect provider.
func (w *wiring) newOIDCProvider(f *federationServices) error {
	var err error
	f.oidcService, err = oidc.NewService(oidc.Deps{
		Pool: w.pool, Issuer: w.issuer,
		Addresses:     w.ipAllowService, // address rules: application authorize, device approval and collection
		Egress:        w.outboundPolicy, // back-channel sign-out notices
		Notifier:      w.notificationService,
		Limits:        w.entitlementSvc,                 // apps (relying parties)
		AgentStatus:   w.agentService.AgentStatus,       // a suspended agent's tokens introspect inactive
		SessionLive:   w.authService.SessionLive,        // an ended session's tokens introspect inactive and can't be exchanged
		PrincipalLive: w.principalService.PrincipalLive, // a disabled service principal's tokens introspect inactive
		// A CIBA approval is a sign-in: the session it comes through meets the organization's second factor.
		SessionFactors: w.authService.SessionFactorShortfall,
		GrantMaxAge:    w.cfg.SessionMaxAge, // grant bound where the organization sets none
		// The client_credentials grant serves the service principals, then the agents.
		MachineClients: []oidc.MachineClient{w.principalService, w.agentService},
	})
	if err != nil {
		return fmt.Errorf("oidc service: %w", err)
	}
	return nil
}

// newSocialSignIn builds social sign-in.
func (w *wiring) newSocialSignIn(f *federationServices) error {
	var err error
	f.socialService, err = social.NewService(social.Deps{
		Pool: w.pool, Auth: w.authService, Cipher: w.sharedCipher,
		Capture: w.domainVerifyService, // social sign-up
		Egress:  w.outboundPolicy, AppBaseURL: w.cfg.AppBaseURL,
		// The callback sets the SSO cookie before redirecting, so an unvalidated
		// return_to would be an open redirect on the auth domain.
		ReturnOrigins: w.hostedReturnOrigins(),
		Platform:      platformSocialProviders(w.cfg),
	})
	if err != nil {
		return fmt.Errorf("social service: %w", err)
	}
	return nil
}

// hostedReturnOrigins are where a sign-in started on the hosted login may
// return to. AllowedOrigins is already the vetted browser origin set
// (Validate() refuses a wildcard outside dev).
func (w *wiring) hostedReturnOrigins() []string {
	return append([]string{w.cfg.AppBaseURL, w.cfg.LoginBaseURL}, w.cfg.AllowedOrigins()...)
}

// newSSO builds single sign-on: the organizations' SAML and OpenID Connect
// connections, and Qeet ID's SAML identity provider.
func (w *wiring) newSSO(f *federationServices) error {
	cfg := w.cfg
	var err error
	if f.samlService, err = saml.NewService(saml.Deps{
		Pool: w.pool, Auth: w.authService,
		Cipher: w.sharedCipher, // the connections' SP encryption keys
		Gate:   w.entitlementSvc, Egress: w.outboundPolicy, AppBaseURL: cfg.AppBaseURL,
		// A sign-in started on the hosted login returns there, under the hosted social sign-in's allowlist.
		LoginBaseURL: cfg.LoginBaseURL, ReturnOrigins: w.hostedReturnOrigins(),
	}); err != nil {
		return fmt.Errorf("saml service: %w", err)
	}
	if f.oidcSSOService, err = oidcsso.NewService(oidcsso.Deps{
		Pool: w.pool, Auth: w.authService, Cipher: w.sharedCipher, Gate: w.entitlementSvc,
		Egress: w.outboundPolicy, AppBaseURL: cfg.AppBaseURL,
		LoginBaseURL: cfg.LoginBaseURL, ReturnOrigins: w.hostedReturnOrigins(),
	}); err != nil {
		return fmt.Errorf("oidc connection service: %w", err)
	}
	keyPEM, certPEM, err := samlIdPIdentity(cfg)
	if err != nil {
		return fmt.Errorf("saml idp: %w", err)
	}
	if f.samlIdP, err = saml.NewIdP(saml.IdPDeps{
		Pool: w.pool, KeyPEM: keyPEM, CertPEM: certPEM, LoginBaseURL: cfg.LoginBaseURL, Sessions: w.authService,
		// An assertion is signed under the same address rules and second factor as an OIDC authorize.
		Addresses: w.ipAllowService, Factors: w.authService, Gate: w.entitlementSvc,
	}); err != nil {
		return fmt.Errorf("saml idp: %w", err)
	}
	return nil
}

// newDirectorySync builds SCIM and LDAP and the directory view over both.
// Both report their operations to the directory's store and map profiles
// through it, so it is built first; the view then lists their connections.
func (w *wiring) newDirectorySync(f *federationServices) error {
	store, err := directory.NewStore(w.pool)
	if err != nil {
		return fmt.Errorf("directory store: %w", err)
	}
	if f.scimService, err = scim.NewService(scim.Deps{
		Pool: w.pool, Users: w.userRepo, Signals: w.sessionSignals,
		Gate:   w.entitlementSvc, // SCIM
		Seats:  w.inviteService,  // seats: the same, through a directory-managed group
		Mapper: store, Observer: store,
	}); err != nil {
		return fmt.Errorf("scim service: %w", err)
	}
	if f.ldapService, err = ldap.NewService(ldap.Deps{
		Pool: w.pool, Auth: w.authService, Cipher: w.sharedCipher,
		Gate: w.entitlementSvc, Mapper: store, Observer: store, Egress: w.outboundPolicy,
		AllowSkipTLSVerify: w.cfg.IsDev(), // skip_tls_verify is a dev-only escape hatch
	}); err != nil {
		return fmt.Errorf("ldap service: %w", err)
	}
	if f.directoryService, err = directory.NewService(store, f.scimService, f.ldapService); err != nil {
		return fmt.Errorf("directory service: %w", err)
	}
	return nil
}

// federationHandlers serves the federation context.
func (w *wiring) federationHandlers(d *Deps) error {
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
	return nil
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
