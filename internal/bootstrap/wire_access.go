package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
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
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
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
	authService          *authentication.Service
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
	// sensitiveThrottle is the tight per-user limit on routes that dispatch an
	// SMS or email to a caller-supplied address or check a password, shared by
	// sign-in and verification; pairingThrottle the per-address limit on
	// pairing-code claims, where a wrong code is a guess.
	sensitiveThrottle func(http.Handler) http.Handler
	pairingThrottle   func(http.Handler) http.Handler
}

// newAccess builds the access context's services, after the directories,
// operations, developer and identity services they are built from. The
// passkey relying party is built first: second factors need it, sign-in needs
// second factors, and the passkey service needs sign-in.
func (w *wiring) newAccess() error {
	a, cfg, pool := w.accessServices, w.cfg, w.pool
	var err error
	a.policyRepo = authpolicy.NewSecurityPolicies(pool, cfg.SessionMaxAge, cfg.SessionIdleTimeout)
	a.riskService = risk.NewService(pool)
	a.botService = bot.NewService(pool)
	a.rebacService = rebac.NewService(pool) // fine-grained (relationship) authorization
	a.decisionLog = decisionlog.New(pool)   // the decisions organizations ask for, kept 30 days
	a.ipAllowService = ipallow.NewService(pool)
	a.sensitiveThrottle = w.routeLimiter(sensitiveLimit).MiddlewareBy("sensitive", ratelimit.PerUser)
	a.pairingThrottle = w.routeLimiter(pairingLimit).MiddlewareBy("pairing", ratelimit.PerIP)
	// Alert the affected user in-app on lockout.
	if a.threatService, err = threat.NewService(pool, w.notificationService); err != nil {
		return fmt.Errorf("threats: %w", err)
	}
	// Attribute-based access control, a plan feature, with relation conditions.
	if a.abacService, err = abac.NewService(pool, w.entitlementSvc, a.rebacService.Check); err != nil {
		return fmt.Errorf("abac: %w", err)
	}
	// Roles: custom roles and seats by plan; a guest's last role taken ends
	// their sessions there, announced.
	if a.rbacService, err = rbac.NewService(a.rbacRepo, rbac.ServiceDeps{
		Emitter: w.webhookService.Enqueue, Limits: w.entitlementSvc, Seats: w.inviteService, Signals: w.sessionSignals,
	}); err != nil {
		return fmt.Errorf("roles: %w", err)
	}
	// One decision across the three engines (an ABAC deny refuses, then any
	// allow): the route guard, /v1/check, the relationship check and AuthZEN.
	a.decider = decide.New(a.rbacRepo, a.rebacService, a.abacService)
	if a.authzenService, err = authzen.NewService(a.rbacRepo, a.rebacService, a.decider, a.decisionLog); err != nil {
		return fmt.Errorf("authzen: %w", err)
	}
	relyingParty, err := passkey.NewRelyingParty(pool, newWebAuthn(cfg))
	if err != nil {
		return fmt.Errorf("passkey relying party: %w", err)
	}
	if err := w.newSecondFactors(relyingParty); err != nil {
		return err
	}
	// People asking for a role, and administrators answering, in the console or
	// on their linked phones: approving gives the role through RBAC; a
	// time-limited grant is taken back by AccessRequestJobs.
	if a.accessRequestService, err = accessrequest.NewService(pool, a.rbacService, a.rbacRepo, w.notificationService, a.mfaService); err != nil {
		return fmt.Errorf("access requests: %w", err)
	}
	if err := w.newSignIn(); err != nil {
		return err
	}
	if a.passkeyService, err = passkey.NewService(passkey.Deps{
		RelyingParty: relyingParty, Auth: a.authService, Policy: w.authPolicyService, Invitations: w.inviteService,
		Sender: w.sender, Capture: w.domainVerifyService,
	}); err != nil {
		return fmt.Errorf("passkeys: %w", err)
	}
	return w.newRecovery()
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

// newSecondFactors builds the second-factor service: its sealed secrets, the
// push services to the iOS and Android apps, passkeys through relyingParty,
// SMS codes only on plans that include them and no code a provider can't
// deliver.
func (w *wiring) newSecondFactors(relyingParty *passkey.RelyingParty) error {
	cfg := w.cfg
	d := mfa.Deps{
		Issuer: cfg.JWTIssuer, Sender: w.sender, Cipher: w.sharedCipher, Plan: w.entitlementSvc,
		Deliverable: w.deliverable(), WebAuthn: relyingParty,
	}
	if cfg.APNsAuthKey != "" {
		d.APNs = &mfa.APNsConfig{AuthKey: cfg.APNsAuthKey, KeyID: cfg.APNsKeyID, TeamID: cfg.APNsTeamID,
			BundleID: cfg.APNsBundleID, Sandbox: cfg.APNsSandbox}
	}
	if cfg.FCMServiceAccount != "" {
		d.FCM = &mfa.FCMConfig{ServiceAccountJSON: cfg.FCMServiceAccount}
	}
	svc, err := mfa.NewService(w.pool, d)
	if err != nil {
		return fmt.Errorf("second factors: %w", err)
	}
	w.mfaService = svc
	if d.APNs != nil {
		slog.Info("push to the iOS app enabled (APNs)", "bundle_id", cfg.APNsBundleID, "sandbox", cfg.APNsSandbox)
	}
	if d.FCM != nil {
		slog.Info("push to the Android app enabled (FCM)")
	}
	return nil
}

// newSignIn builds sign-in and sessions with the policies, factors, hooks and
// risk checks that decide them.
func (w *wiring) newSignIn() error {
	cfg, policies := w.cfg, w.authPolicyService
	// Hosted sign-out tells the applications the session signed in to.
	notices, err := oidc.NewLogoutNotices(w.pool, w.issuer)
	if err != nil {
		return fmt.Errorf("sign-out notices: %w", err)
	}
	svc, err := authentication.New(authentication.Deps{
		Pool: w.pool, Users: w.userRepo, Tokens: w.issuer, Cipher: w.sharedCipher,
		MFA:  w.mfaService,  // a second factor where the account holds one or must
		Risk: w.riskService, // every sign-in assessed; a risky one skips no factor
		// The organization's self-registration and password check, the methods it
		// allows, its remembered devices (adaptive MFA) and its sign-in lockout,
		// which may only be stricter than the platform's.
		Registration: policies, Methods: policies, Devices: policies,
		Lockout: func(ctx context.Context, organizationID uuid.UUID) (authentication.Lockout, error) {
			l, err := policies.SignInLockout(ctx, organizationID)
			return authentication.Lockout(l), err
		},
		Capture:   w.domainVerifyService, // password sign-in, sign-up, hosted registration
		Addresses: w.ipAllowService,      // every sign-in to an organization, and every renewal
		Anomalies: w.threatService,       // sign-in locks and spraying sources
		Sender:    w.sender,              // the code that confirms a risky sign-in with no factor
		LoginHook: w.authHookService,     // an organization's Actions/Hooks gate; none configured runs nothing
		SignOut:   notices,
		Signals:   w.sessionSignals,
		// Who an organization's "second factor for administrators" applies to.
		MemberPermissions: identitylink.MemberPermissions(),
		SessionMaxAge:     cfg.SessionMaxAge, SessionIdle: cfg.SessionIdleTimeout,
		// A rotated refresh token sent again within the grace gets its
		// rotation's pair, for a client that renewed twice at once or lost the
		// answer.
		RefreshReuseGrace: cfg.RefreshTokenReuseGrace,
	})
	if err != nil {
		return fmt.Errorf("sign-in: %w", err)
	}
	w.authService = svc
	return nil
}

// newRecovery builds password resets and magic links: one password check for every path that sets a
// password (organization or platform rules, strength, breach check), magic links only where the
// organization allows them, and hosted-login resets that link back to it.
func (w *wiring) newRecovery() error {
	svc, err := recovery.NewService(w.pool, recovery.Deps{
		Sender: w.sender, TTL: time.Hour, BaseAppURL: w.cfg.AppBaseURL, LoginBaseURL: w.cfg.LoginBaseURL,
		Rules: w.authPolicyService, MagicLinks: w.authPolicyService, Capture: w.domainVerifyService,
		Signals: w.sessionSignals, MagicPerAddress: w.limits.magicAddress, MagicPerCaller: w.limits.magicCaller,
		ResetPerAddress: w.limits.resetAddress,
	})
	if err != nil {
		return fmt.Errorf("recovery: %w", err)
	}
	w.recoveryService = svc
	return nil
}

// breachChecker is the breached-password check (Have I Been Pwned
// k-anonymity), or none when BREACHED_PASSWORD_CHECK turns it off. It fails
// open on a HIBP outage, counted in breached_password_check_allowed_on_error_total,
// and only the 5-character SHA-1 prefix leaves the process.
func breachChecker(cfg *config.Config) authpolicy.BreachChecker {
	if !cfg.BreachedPasswordCheck {
		if !cfg.IsDev() {
			slog.Warn("breached-password check is off (BREACHED_PASSWORD_CHECK=false): new passwords are not checked against known breaches")
		}
		return authpolicy.NoBreachCheck{}
	}
	slog.Info("breached-password check enabled (HIBP k-anonymity; fail-open)", "min_count", cfg.BreachedPasswordMinCount)
	return hibp.New(&http.Client{Timeout: 3 * time.Second}, cfg.BreachedPasswordAPIURL, cfg.BreachedPasswordMinCount)
}

// accessHandlers serves the access context.
func (w *wiring) accessHandlers(d *Deps) error {
	cfg := w.cfg
	d.AuthPolicy = &authpolicy.Handler{Service: w.authPolicyService}
	d.Auth = &authentication.Handler{Service: w.authService, Validate: w.validate, CookieSecure: !cfg.IsDev(), Bot: w.botService, GeoCountryHeader: cfg.GeoCountryHeader, ActOnCheck: w.rbacRepo.CheckActOn,
		Throttle: w.sensitiveThrottle}
	d.RBAC = &rbac.Handler{Repo: w.rbacRepo, Service: w.rbacService, Validate: w.validate, Decider: w.decider, Decisions: w.decisionLog}
	d.AccessRequest = &accessrequest.Handler{Service: w.accessRequestService, GrantCheck: w.rbacRepo.CheckGrantRole}
	d.DecisionLog = &decisionlog.Handler{Log: w.decisionLog}
	d.RBACChecker = w.decider
	d.Recovery = &recovery.Handler{Service: w.recoveryService, AuthService: w.authService, DevMode: cfg.IsDev(), CookieSecure: !cfg.IsDev(), PublicBaseURL: cfg.PublicBaseURL}
	d.MFA = &mfa.Handler{Service: w.mfaService, WebAuthn: w.passkeyService, ActOnCheck: w.rbacRepo.CheckActOn, PairingThrottle: w.pairingThrottle}
	d.Policy = &authpolicy.SecurityPolicyHandler{Repo: w.policyRepo}
	d.Passkey = &passkey.Handler{Service: w.passkeyService, CookieSecure: !cfg.IsDev()}
	d.IPAllow = &ipallow.Handler{Service: w.ipAllowService}
	d.Threat = &threat.Handler{Service: w.threatService}
	d.Bot = &bot.Handler{Service: w.botService}
	d.Risk = &risk.Handler{Service: w.riskService}
	d.ABAC = &abac.Handler{Service: w.abacService, Decisions: w.decisionLog}
	d.ReBAC = &rebac.Handler{Service: w.rebacService, Decider: w.decider, Decisions: w.decisionLog}
	d.AuthZEN = &authzen.Handler{Service: w.authzenService}
	return errors.Join(d.Auth.Check(), d.MFA.Check())
}

// routeLimiter builds the limit l in process, or shared across replicas
// through the rate-limit store when one is configured, as the router does.
func (w *wiring) routeLimiter(l ratelimits.BuiltInLimit) *ratelimit.Limiter {
	if w.limits.store != nil {
		return ratelimit.NewWithStore(w.limits.store, l.Rate, l.Capacity)
	}
	return ratelimit.New(l.Rate, l.Capacity)
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
			purged, err := authentication.PurgeEndedSessions(ctx, pool, authentication.SessionRetention, signals)
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
			n, err := authentication.ClearRefreshRetries(ctx, pool)
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
		"GET /v1/me/permissions",
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
