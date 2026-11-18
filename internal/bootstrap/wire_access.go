package bootstrap

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authzen"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rebac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkey"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot"
	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/worker"
)

// accessServices are the access context's: sign-in and sessions, second
// factors and passkeys, recovery, sign-in policy, threats and every
// authorization engine.
type accessServices struct {
	rbacRepo             *rbac.Repository
	rbacService          *rbac.Service
	policyRepo           *authpolicy.SecurityPolicies
	recoveryService      *recovery.Service
	authService          *auth.Service
	authPolicyService    *authpolicy.Service
	mfaService           *mfa.Service
	threatService        *threat.Service
	accessRequestService *accessrequest.Service
	riskService          *risk.Service
	botService           *bot.Service
	rebacService         *rebac.Service
	abacService          *abac.Service
	decider              *decide.Decider
	authzenService       *authzen.Service
	decisionLog          *decisionlog.Log
	passkeyService       *passkey.Service
	ipAllowService       *ipallow.Service
}

// newAccess builds the access context's services.
func (w *wiring) newAccess() *accessServices {
	a := &accessServices{
		rbacRepo:          rbac.NewRepository(w.pool),
		policyRepo:        authpolicy.NewSecurityPolicies(w.pool),
		recoveryService:   recovery.NewService(w.pool, w.sender, time.Hour, w.cfg.AppBaseURL),
		authService:       auth.NewService(w.pool, w.userRepo, w.issuer),
		authPolicyService: authpolicy.NewService(w.pool),
		mfaService:        mfa.NewService(w.pool, w.cfg.JWTIssuer, w.sender),
		threatService:     threat.NewService(w.pool),
		riskService:       risk.NewService(w.pool),
		botService:        bot.NewService(w.pool),
		rebacService:      rebac.NewService(w.pool), // fine-grained (relationship) authorization
		abacService:       abac.NewService(w.pool),  // attribute-based access control (policy store + PDP)
		decisionLog:       decisionlog.New(w.pool),  // the decisions organizations ask for, kept 30 days
		ipAllowService:    ipallow.NewService(w.pool),
	}
	a.rbacService = rbac.NewService(a.rbacRepo)
	// People asking for a role, and administrators answering, in the console or
	// on the phone: approving gives the role through RBAC; a time-limited grant
	// is taken back by AccessRequestJobs.
	a.accessRequestService = accessrequest.NewService(w.pool, a.rbacService, a.rbacRepo)
	// One decision across the three engines (an ABAC deny refuses, then any
	// allow): the route guard, /v1/check, the relationship check and AuthZEN.
	a.decider = decide.New(a.rbacRepo, a.rebacService, a.abacService)
	a.authzenService = authzen.NewService(a.rbacRepo, a.rebacService, a.decider) // OpenID AuthZEN PDP facade
	a.passkeyService = passkey.NewService(w.pool, newWebAuthn(w.cfg), a.authService)
	return a
}

// newWebAuthn returns the passkey relying party cfg names, exiting when it is
// not a valid one.
func newWebAuthn(cfg *config.Config) *webauthn.WebAuthn {
	rpID, rpDisplayName, rpOrigins := cfg.WebAuthnRP()
	// UserVerification must be Required: go-webauthn checks the UV flag only on
	// strict equality, and without it a passkey proves possession alone. Passkey-only
	// accounts have no password, so this is the whole credential. The registration
	// ceremonies set it themselves.
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		slog.Error("webauthn init", "err", err)
		os.Exit(1)
	}
	return wa
}

// wireAccess connects the access context's services to the rest.
func (w *wiring) wireAccess() {
	w.policyRepo.SetSessionDefaults(w.cfg.SessionMaxAge, w.cfg.SessionIdleTimeout)
	w.wireRecovery()
	w.wireBreachCheck()
	w.wireMFA()
	w.wireSignIn()
	w.wireAuthorization()
	w.passkeyService.SetMethodPolicy(w.authPolicyService)    // offer and accept new passkeys only where the organization allows them
	w.passkeyService.SetInvitations(w.inviteService)         // accept an invitation with a passkey
	w.passkeyService.SetSender(w.sender)                     // tell the account holder a passkey was added or removed
	w.passkeyService.SetDomainCapture(w.domainVerifyService) // passkey sign-in and sign-up
}

// wireRecovery connects password resets and magic links.
func (w *wiring) wireRecovery() {
	w.recoveryService.SetHostedLogin(w.cfg.LoginBaseURL) // resets requested there link back to it
	// One password check for every path that sets a password:
	// authPolicyService.ValidateForOrganization (organization rules or platform baseline,
	// strength baseline, breach check).
	w.recoveryService.SetPasswordRules(w.authPolicyService)   // password reset
	w.recoveryService.SetMagicLinkPolicy(w.authPolicyService) // magic links only where the organization allows them, with its lifetime
	w.recoveryService.SetSessionSignals(w.sessionSignals)
	w.recoveryService.SetDomainCapture(w.domainVerifyService) // password reset, magic links
	w.recoveryService.SetMagicLinkLimits(w.limits.magicAddress, w.limits.magicCaller)
	w.recoveryService.SetResetLimit(w.limits.resetAddress)
}

// wireBreachCheck turns on the breached-password check (Have I Been Pwned
// k-anonymity), unless BREACHED_PASSWORD_CHECK turns it off. It fails open on
// a HIBP outage, counted in breached_password_check_allowed_on_error_total,
// and only the 5-character SHA-1 prefix leaves the process.
func (w *wiring) wireBreachCheck() {
	cfg := w.cfg
	if cfg.BreachedPasswordCheck {
		breachChecker := hibp.New(&http.Client{Timeout: 3 * time.Second}, cfg.BreachedPasswordAPIURL, cfg.BreachedPasswordMinCount)
		w.authPolicyService.SetBreachChecker(breachChecker)
		slog.Info("breached-password check enabled (HIBP k-anonymity; fail-open)", "min_count", cfg.BreachedPasswordMinCount)
	} else if !cfg.IsDev() {
		slog.Warn("breached-password check is off (BREACHED_PASSWORD_CHECK=false): new passwords are not checked against known breaches")
	}
}

// wireMFA connects second factors: their sealed secrets, the push services
// to the iOS and Android apps, passkeys and the plan.
func (w *wiring) wireMFA() {
	cfg := w.cfg
	w.mfaService.SetCipher(w.sharedCipher)
	if cfg.APNsAuthKey != "" {
		if err := w.mfaService.EnableAPNs(mfa.APNsConfig{
			AuthKey: cfg.APNsAuthKey, KeyID: cfg.APNsKeyID, TeamID: cfg.APNsTeamID,
			BundleID: cfg.APNsBundleID, Sandbox: cfg.APNsSandbox,
		}); err != nil {
			slog.Error("init apns", "err", err)
			os.Exit(1)
		}
		slog.Info("push to the iOS app enabled (APNs)", "bundle_id", cfg.APNsBundleID, "sandbox", cfg.APNsSandbox)
	}
	if cfg.FCMServiceAccount != "" {
		if err := w.mfaService.EnableFCM(mfa.FCMConfig{ServiceAccountJSON: cfg.FCMServiceAccount}); err != nil {
			slog.Error("init fcm", "err", err)
			os.Exit(1)
		}
		slog.Info("push to the Android app enabled (FCM)")
	}
	w.mfaService.SetWebAuthn(w.passkeyService) // a passkey can meet a sign-in's second-factor challenge
	w.mfaService.SetPlan(w.entitlementSvc)     // SMS codes only on plans that include them
	if w.mail.routed {
		w.mfaService.SetDeliveryCheck(w.mail.transport.Configured) // refuse codes no provider can deliver
	}
}

// wireSignIn connects sign-in and sessions to the policies, factors, hooks
// and risk checks that decide them.
func (w *wiring) wireSignIn() {
	w.authService.SetMFA(w.mfaService)                       // gate password login on a second factor when enrolled
	w.authService.SetRegistrationPolicy(w.authPolicyService) // gate hosted signup + the password check (signup, register, change)
	w.authService.SetMethodPolicy(w.authPolicyService)       // password sign-in only where the organization allows it
	w.authService.SetDevicePolicy(w.authPolicyService)       // gate adaptive MFA (trusted-device skip)
	// Who an organization's "second factor for administrators" applies to.
	w.authService.SetMemberPermissions(identitylink.MemberPermissions())
	// Sign-in lockout: the platform's defaults and bounds are the packages' own;
	// an organization's settings live in its authentication policy and may only
	// be stricter than the defaults.
	w.authService.SetLockoutSource(func(ctx context.Context, organizationID uuid.UUID) (auth.Lockout, error) {
		l, err := w.authPolicyService.SignInLockout(ctx, organizationID)
		return auth.Lockout(l), err
	})
	w.authService.SetLoginHook(w.authHookService)     // synchronous Actions/Hooks gate (no-op until configured)
	w.authService.SetAnomalyRecorder(w.threatService) // record sign-in lock and spraying-source anomalies
	w.authService.SetRiskAssessor(w.riskService)      // assess every sign-in; a risky one skips no factor
	w.authService.SetSender(w.sender)                 // email the code that confirms a risky sign-in with no factor
	// A rotated refresh token sent again within the grace gets its rotation's
	// pair, for a client that renewed twice at once or lost the answer.
	w.authService.SetRefreshReuseGrace(w.cfg.RefreshTokenReuseGrace, w.sharedCipher)
	w.authService.SetSessionSignals(w.sessionSignals)
	w.authService.SetSessionLifetime(w.cfg.SessionMaxAge, w.cfg.SessionIdleTimeout) // session bounds where the organization sets none
	w.authService.SetAddressPolicy(w.ipAllowService)                                // address rules: every sign-in to an organization, and every renewal
	w.authService.SetSignOutNotifier(w.oidcService)                                 // tell applications when someone signs out of the hosted login
	w.authService.SetDomainCapture(w.domainVerifyService)                           // password sign-in, sign-up, hosted registration
}

// wireAuthorization connects roles, access requests and the relationship and
// attribute engines.
func (w *wiring) wireAuthorization() {
	w.accessRequestService.SetNotifier(w.notificationService)
	w.accessRequestService.SetPhoneNotifier(w.mfaService) // approvers' linked phones (APNs, FCM)
	w.threatService.SetNotifier(w.notificationService)    // alert the affected user in-app on lockout
	w.abacService.SetRelationCheck(w.rebacService.Check)  // relation conditions
	w.abacService.SetPlanGate(w.entitlementSvc)           // ABAC
	w.authzenService.Decisions = w.decisionLog
	// A guest's last role taken ends their sessions there, announced.
	w.rbacService.SetSessionSignals(w.sessionSignals)
	w.rbacService.SetEmitter(w.webhookService.Enqueue)
	w.rbacService.SetSeatGuard(w.inviteService)    // seats: a person's first role, directly
	w.rbacService.SetPlanLimiter(w.entitlementSvc) // custom_roles
}

// accessHandlers serves the access context.
func (w *wiring) accessHandlers(d *Deps) {
	cfg := w.cfg
	d.AuthPolicy = &authpolicy.Handler{Service: w.authPolicyService}
	d.Auth = &auth.Handler{Service: w.authService, Validate: w.validate, CookieSecure: !cfg.IsDev(), Bot: w.botService, GeoCountryHeader: cfg.GeoCountryHeader, ActOnCheck: w.rbacRepo.CheckActOn}
	d.RBAC = &rbac.Handler{Repo: w.rbacRepo, Service: w.rbacService, Validate: w.validate, Decider: w.decider, Decisions: w.decisionLog}
	d.AccessRequest = &accessrequest.Handler{Service: w.accessRequestService, GrantCheck: w.rbacRepo.CheckGrantRole}
	d.DecisionLog = &decisionlog.Handler{Log: w.decisionLog}
	d.RBACChecker = w.decider
	d.Recovery = &recovery.Handler{Service: w.recoveryService, AuthService: w.authService, DevMode: cfg.IsDev(), CookieSecure: !cfg.IsDev(), PublicBaseURL: cfg.PublicBaseURL}
	d.MFA = &mfa.Handler{Service: w.mfaService, WebAuthn: w.passkeyService, ActOnCheck: w.rbacRepo.CheckActOn}
	d.Policy = &authpolicy.SecurityPolicyHandler{Repo: w.policyRepo}
	d.Passkey = &passkey.Handler{Service: w.passkeyService, CookieSecure: !cfg.IsDev()}
	d.IPAllow = &ipallow.Handler{Service: w.ipAllowService}
	d.Threat = &threat.Handler{Service: w.threatService}
	d.Bot = &bot.Handler{Service: w.botService}
	d.Risk = &risk.Handler{Service: w.riskService}
	d.ABAC = &abac.Handler{Service: w.abacService, Decisions: w.decisionLog}
	d.ReBAC = &rebac.Handler{Service: w.rebacService, Decider: w.decider, Decisions: w.decisionLog}
	d.AuthZEN = &authzen.Handler{Service: w.authzenService}
}

// accessPolicies are the access context's routes whose policy is neither a
// permission nor user-only: answering an access request gives a role or
// refuses it, a person's decision recorded as theirs, so it needs role.write
// and no machine credential.
func accessPolicies() map[string]rbac.RoutePolicy {
	answer := rbac.RoutePolicy{UserPermission: "role.write", ApplicationScope: "role.write", AllowUser: true}
	return map[string]rbac.RoutePolicy{
		"POST /v1/organizations/{organizationID}/access-requests/{id}/approve": answer,
		"POST /v1/organizations/{organizationID}/access-requests/{id}/deny":    answer,
	}
}

// sessionExpiryCleanupJob removes expired sessions, announcing each through
// signals as session.revoked (reason expired).
func sessionExpiryCleanupJob(pool *pgxpool.Pool, signals *sessionsignal.Signaller) worker.Scheduled {
	return worker.Scheduled{
		Name:     "session-expiry-cleanup",
		Interval: 15 * time.Minute,
		Run: func(ctx context.Context) error {
			purged, err := auth.PurgeEndedSessions(ctx, pool, auth.SessionRetention, signals)
			if err != nil {
				return err
			}
			slog.Info("sessions cleaned", "sessions", purged.Sessions, "login_sessions", purged.LoginSessions,
				"ceremonies", purged.Ceremonies, "trusted_devices", purged.TrustedDevices)
			return nil
		},
	}
}

// refreshRetryCleanupJob clears the pairs kept from refresh rotations: a
// rotation's kept pair is needed only for the refresh reuse grace.
func refreshRetryCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "refresh-retry-cleanup",
		Interval: 5 * time.Minute,
		Run: func(ctx context.Context) error {
			n, err := auth.ClearRefreshRetries(ctx, pool)
			if err != nil {
				return err
			}
			slog.Info("kept refresh rotations cleared", "cleared", n)
			return nil
		},
	}
}

// mfaCleanupJob removes expired one-time codes, push requests and pairing
// codes.
func mfaCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "mfa-cleanup",
		Interval: time.Hour,
		Run: func(ctx context.Context) error {
			codes, err := mfa.PurgeExpiredOTPCodes(ctx, pool, mfa.OTPCodeRetention)
			if err != nil {
				return err
			}
			push, err := mfa.PurgeExpiredPushChallenges(ctx, pool, mfa.OTPCodeRetention)
			if err != nil {
				return err
			}
			pairings, err := mfa.PurgeExpiredPushPairings(ctx, pool, mfa.OTPCodeRetention)
			if err != nil {
				return err
			}
			slog.Info("expired MFA codes and push requests cleaned", "codes", codes, "push_requests", push,
				"pairing_codes", pairings)
			return nil
		},
	}
}

// signInHistoryCleanupJob removes sign-in history past its retention.
func signInHistoryCleanupJob(pool *pgxpool.Pool) worker.Scheduled {
	return worker.Scheduled{
		Name:     "sign-in-history-cleanup",
		Interval: 24 * time.Hour,
		Run: func(ctx context.Context) error {
			n, err := risk.PurgeSignInHistory(ctx, pool, risk.SignInHistoryRetention)
			if err != nil {
				return err
			}
			slog.Info("sign-in history cleaned", "deleted", n)
			return nil
		},
	}
}

// accessPermissions are the access context's routes and the user permission
// each needs, as userPermissionMap lists them.
func accessPermissions() map[string]string {
	return map[string]string{
		// A member's remembered devices, in the administrator's organization.
		"GET /v1/users/{id}/trusted-devices":               "user.read",
		"DELETE /v1/users/{id}/trusted-devices":            "user.credentials",
		"DELETE /v1/users/{id}/trusted-devices/{deviceID}": "user.credentials",
		// A member's linked phones, in the administrator's organization.
		"GET /v1/users/{id}/push-devices":               "user.read",
		"DELETE /v1/users/{id}/push-devices/{deviceID}": "user.credentials",

		// RBAC: roles, permissions, assignments, checks.
		"GET /v1/permissions":                                                     "role.read",
		"GET /v1/organizations/{organizationID}/roles":                            "role.read",
		"GET /v1/organizations/{organizationID}/roles/{roleID}/holders":           "role.read",
		"POST /v1/organizations/{organizationID}/roles":                           "role.write",
		"PATCH /v1/organizations/{organizationID}/roles/{roleID}":                 "role.write",
		"DELETE /v1/organizations/{organizationID}/roles/{roleID}":                "role.write",
		"PUT /v1/organizations/{organizationID}/roles/{roleID}/permissions":       "role.write",
		"GET /v1/roles/{roleID}/permissions":                                      "role.read",
		"POST /v1/roles/{roleID}/permissions/{permID}":                            "role.write",
		"DELETE /v1/roles/{roleID}/permissions/{permID}":                          "role.write",
		"POST /v1/users/{userID}/organizations/{organizationID}/roles/{roleID}":   "role.write",
		"DELETE /v1/users/{userID}/organizations/{organizationID}/roles/{roleID}": "role.write",

		// Access requests: reading them. Answering one is in RoutePolicies.
		"GET /v1/organizations/{organizationID}/access-requests":            "role.read",
		"GET /v1/organizations/{organizationID}/access-requests/{id}":       "role.read",
		"GET /v1/users/{userID}/organizations/{organizationID}/permissions": "role.read",
		"GET /v1/check": "role.read",
		"GET /v1/organizations/{organizationID}/groups/{groupID}/roles": "role.read",

		// ABAC: attribute-based access control policy CRUD.
		// Reads are gated on policy.read; mutations on policy.write. The
		// evaluate endpoint is a PDP call and is ungated beyond organization scope
		// (it gates itself via httpx.PathOrganization in the handler).
		"GET /v1/organizations/{organizationID}/abac/policies":                                  "policy.read",
		"POST /v1/organizations/{organizationID}/abac/policies":                                 "policy.write",
		"GET /v1/organizations/{organizationID}/abac/policies/{id}":                             "policy.read",
		"PATCH /v1/organizations/{organizationID}/abac/policies/{id}":                           "policy.write",
		"DELETE /v1/organizations/{organizationID}/abac/policies/{id}":                          "policy.write",
		"GET /v1/organizations/{organizationID}/abac/policies/{id}/versions":                    "policy.read",
		"POST /v1/organizations/{organizationID}/abac/policies/{id}/versions/{version}/restore": "policy.write",
		"POST /v1/organizations/{organizationID}/abac/evaluate":                                 "policy.read",
		"POST /v1/organizations/{organizationID}/access/v1/evaluation":                          "role.read",
		"POST /v1/organizations/{organizationID}/access/v1/evaluations":                         "role.read",
		"GET /v1/organizations/{organizationID}/authorization/decisions":                        "policy.read",

		// ReBAC: relationship tuples + identity graph.
		// Reads are gated on role.read (structural authz data). Writes/deletes
		// and the /check endpoint are ungated beyond organization scope (they gate
		// themselves via httpx.PathOrganization + the relation-tuple payload).
		"GET /v1/organizations/{organizationID}/relation-tuples":         "role.read",
		"POST /v1/organizations/{organizationID}/relation-tuples":        "role.write",
		"DELETE /v1/organizations/{organizationID}/relation-tuples/{id}": "role.write",
		"POST /v1/organizations/{organizationID}/relation-tuples/check":  "role.read",
		"GET /v1/organizations/{organizationID}/relation-tuples/graph":   "role.read",
		"GET /v1/organizations/{organizationID}/relation-tuples/types":   "role.read",
		"GET /v1/organizations/{organizationID}/relation-tuples/objects": "role.read",

		// Roles given through a group.
		"POST /v1/organizations/{organizationID}/groups/{groupID}/roles/{roleID}":   "role.write",
		"DELETE /v1/organizations/{organizationID}/groups/{groupID}/roles/{roleID}": "role.write",

		// The organization's count of remembered devices (adaptive MFA "remember
		// this device"), not the OAuth device grants.
		"GET /v1/auth/trusted-devices/count": "connection.read",

		// Security and sign-in policy, IP rules, threats.
		"GET /v1/organizations/{organizationID}/policy":                           "policy.read",
		"PUT /v1/organizations/{organizationID}/policy":                           "policy.write",
		"PATCH /v1/organizations/{organizationID}/policy":                         "policy.write",
		"GET /v1/organizations/{organizationID}/auth-policy":                      "policy.read",
		"GET /v1/organizations/{organizationID}/auth-policy/usage":                "policy.read",
		"PUT /v1/organizations/{organizationID}/auth-policy":                      "policy.write",
		"GET /v1/organizations/{organizationID}/ip-rules":                         "policy.read",
		"POST /v1/organizations/{organizationID}/ip-rules":                        "policy.write",
		"DELETE /v1/organizations/{organizationID}/ip-rules/{ruleID}":             "policy.write",
		"PUT /v1/organizations/{organizationID}/ip-rules/config":                  "policy.write",
		"POST /v1/organizations/{organizationID}/ip-rules/check":                  "policy.read",
		"GET /v1/organizations/{organizationID}/security/anomalies":               "policy.read",
		"GET /v1/organizations/{organizationID}/security/anomalies/summary":       "policy.read",
		"POST /v1/organizations/{organizationID}/security/anomalies/{id}/resolve": "policy.write",
		"GET /v1/organizations/{organizationID}/security/bots":                    "policy.read",
		"GET /v1/organizations/{organizationID}/security/bots/settings":           "policy.read",
		"PUT /v1/organizations/{organizationID}/security/bots/settings":           "policy.write",
		"GET /v1/organizations/{organizationID}/security/risk-settings":           "policy.read",
		"PUT /v1/organizations/{organizationID}/security/risk-settings":           "policy.write",
	}
}

// accessUserOnlyRoutes are the access context's routes of a person's own account or
// resources, which RoutePolicies makes user-only.
func accessUserOnlyRoutes() []string {
	return []string{
		"POST /v1/auth/logout",
		"POST /v1/auth/switch-organization",
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
		"GET /v1/me/access-requests",
		"POST /v1/me/access-requests",
		"GET /v1/me/access-requests/roles",
		"POST /v1/me/access-requests/{id}/cancel",
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
		"POST /v1/mfa/push/step-up",
		"POST /v1/mfa/push/step-up/{id}/complete",
	}
}

// accessStepUps are the access context's routes that need a recent step-up, as
// StepUpRoutes lists them.
func accessStepUps() map[string]mfa.StepUpRule {
	return stepUps(
		[]string{
			// The person's own factors and sign-in methods.
			"POST /v1/mfa/totp/enroll/start",
			"POST /v1/mfa/otp/factors",
			"DELETE /v1/mfa/otp/factors/{id}",
			"POST /v1/mfa/push/devices",
			"DELETE /v1/mfa/push/devices/{id}",
			"POST /v1/mfa/push/pairing",
			"POST /v1/passkeys/register/begin",
			"DELETE /v1/passkeys/{id}",
			"POST /v1/auth/password",
		},
		[]string{
			// Switching the authenticator app off, or replacing its recovery codes.
			"DELETE /v1/mfa/totp",
			"POST /v1/mfa/recovery-codes/regenerate",

			// Sign-in and security policy.
			"PUT /v1/organizations/{organizationID}/policy",
			"PATCH /v1/organizations/{organizationID}/policy",
			"PUT /v1/organizations/{organizationID}/auth-policy",
			"PUT /v1/organizations/{organizationID}/security/risk-settings",
			"PUT /v1/organizations/{organizationID}/security/bots/settings",
			"POST /v1/organizations/{organizationID}/ip-rules",
			"DELETE /v1/organizations/{organizationID}/ip-rules/{ruleID}",
			"PUT /v1/organizations/{organizationID}/ip-rules/config",

			// Handing out authority: what a role can do, who holds it, who is invited
			// to hold it, and the relationship and attribute rules that decide access.
			"POST /v1/roles/{roleID}/permissions/{permID}",
			"DELETE /v1/roles/{roleID}/permissions/{permID}",
			"POST /v1/users/{userID}/organizations/{organizationID}/roles/{roleID}",
			"DELETE /v1/users/{userID}/organizations/{organizationID}/roles/{roleID}",
			"POST /v1/organizations/{organizationID}/groups/{groupID}/roles/{roleID}",
			"POST /v1/organizations/{organizationID}/access-requests/{id}/approve",
			"DELETE /v1/organizations/{organizationID}/groups/{groupID}/roles/{roleID}",
			"POST /v1/organizations/{organizationID}/relation-tuples",
			"DELETE /v1/organizations/{organizationID}/relation-tuples/{id}",
			"PATCH /v1/organizations/{organizationID}/roles/{roleID}",
			"DELETE /v1/organizations/{organizationID}/roles/{roleID}",
			"PUT /v1/organizations/{organizationID}/roles/{roleID}/permissions",
			"POST /v1/organizations/{organizationID}/abac/policies",
			"PATCH /v1/organizations/{organizationID}/abac/policies/{id}",
			"DELETE /v1/organizations/{organizationID}/abac/policies/{id}",
			"POST /v1/organizations/{organizationID}/abac/policies/{id}/versions/{version}/restore",
		},
	)
}
