// Package auth handles login, refresh, logout, and session storage.
// Access & ID tokens are signed with ES256 (asymmetric) and verifiable via the
// public JWKS; see internal/platform/tokens.
package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service signs people in, by every method, and manages their sessions and
// refresh tokens.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	users  *user.Repository
	tokens *tokens.Issuer
	// mfa gates login on a second factor (nil = MFA-at-login off). Set via
	// SetMFA; kept as an interface so package auth doesn't import package mfa.
	mfa MFAEnroller
	// regPolicy gates hosted self-registration and is the password check every
	// password this service sets goes through (nil = self-registration off, and
	// no password can be set). Set via SetRegistrationPolicy; an interface so
	// auth doesn't import authpolicy.
	regPolicy RegistrationPolicy
	// methods decides which sign-in methods an organisation allows (nil = all).
	methods MethodPolicy
	// anomaly receives security signals (nil = recording off). Set via
	// SetAnomalyRecorder; an interface so auth doesn't import the threat package.
	anomaly AnomalyRecorder
	// devicePolicy reports whether a tenant has opted into adaptive MFA
	// (trusted-device skip). nil = always-on MFA. Set via SetDevicePolicy.
	devicePolicy DevicePolicy
	// riskAssessor assesses every sign-in's risk (see risksignin.go). nil = no
	// assessment.
	riskAssessor RiskAssessor
	// sender emails the code that confirms a risky sign-in by someone with no
	// second factor. Set via SetSender; nil refuses such a sign-in.
	sender notifier.Sender
	// loginHook is an optional synchronous policy gate run after credentials
	// verify (nil = no gate). Set via SetLoginHook.
	loginHook LoginHook
	// addresses is the organisations' address rules, asked before any session
	// in an organisation is issued or renewed (nil = no rules). See address.go.
	addresses AddressPolicy
	// signOutNotifier tells applications of a hosted sign-out (nil = none).
	signOutNotifier SignOutNotifier
	// signals announces ended sessions to subscribed applications (nil =
	// announces nothing). Set via SetSessionSignals.
	signals *sessionsignal.Signaller
	// lockout is the platform-wide sign-in lockout configuration, and
	// lockoutSource the per-tenant settings (nil = the platform defaults for
	// every sign-in). See lockout.go.
	lockout       LockoutConfig
	lockoutSource LockoutSource
	// sessionMaxAge and sessionIdle bound a session whose organisation sets
	// no bounds of its own (zero = the platform defaults). See lifetime.go.
	sessionMaxAge time.Duration
	sessionIdle   time.Duration
	// uses throttles the record of sessions' use; see SessionUsed.
	uses sessionUses
	// failures bounds the record of failed sign-ins; see signinaudit.go.
	failures failureBound
	// refreshGrace is how long a rotated refresh token gets its rotation's
	// pair again, kept sealed with refreshCipher (zero or nil = never). See
	// refreshretry.go.
	refreshGrace  time.Duration
	refreshCipher *envelope.Cipher
}

// NewService returns the sign-in and session service.
func NewService(pool *pgxpool.Pool, users *user.Repository, t *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), users: users, tokens: t, lockout: DefaultLockoutConfig(), failures: newFailureBound()}
}

// SetSessionSignals wires the announcement of ended sessions (session.revoked
// webhooks).
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// MFAEnroller is the slice of the MFA service the auth package needs to enforce
// a second factor at login.
type MFAEnroller interface {
	// LoginFactors lists the second factors the user can meet a sign-in
	// challenge with (none: sign in without one). See mfalogin.go.
	// LoginFactorsTx reads them through tx.
	LoginFactors(ctx context.Context, userID uuid.UUID) ([]LoginFactor, error)
	LoginFactorsTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) ([]LoginFactor, error)
	// VerifyForLoginTx checks an authenticator-app, recovery or email/SMS code
	// inside the challenge transaction and returns the kind that matched ("totp",
	// "recovery_code" or "otp"). It returns ("", nil) for a wrong code.
	VerifyForLoginTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (string, error)
	// SendLoginCode sends a code to one of the user's confirmed email/SMS
	// factors for a sign-in to tenantID (nil: none).
	SendLoginCode(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, factorID uuid.UUID) error
	// BeginLoginPasskey starts a passkey assertion for the user's own
	// passkeys; FinishLoginPasskeyTx verifies one inside the challenge
	// transaction (a domain error: not verified).
	BeginLoginPasskey(ctx context.Context, userID uuid.UUID) (uuid.UUID, any, error)
	FinishLoginPasskeyTx(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, credential json.RawMessage) error
	// StartLoginPush sends a push approval request to the user's devices and
	// returns its id and expiry; LoginPushStatusTx reads its state
	// ("pending", "approved", "denied" or "expired") under lock.
	StartLoginPush(ctx context.Context, userID uuid.UUID, ip, ua string) (uuid.UUID, time.Time, error)
	LoginPushStatusTx(ctx context.Context, tx pgx.Tx, userID, challengeID uuid.UUID) (string, error)
	// RecordVerification records that one of the user's sessions met a second
	// factor, stepping that session (and no other) up.
	RecordVerification(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, method string) error
	// StartLoginEnrollment starts an authenticator app for a sign-in's enrolment
	// challenge and returns its secret and provisioning URL. ConfirmLoginEnrollment
	// confirms it with a code and returns new recovery codes, or false for a wrong
	// code. Both run inside the challenge transaction.
	StartLoginEnrollment(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (string, string, error)
	ConfirmLoginEnrollment(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, bool, error)
}

// SetMFA wires the MFA-at-login checker.
func (s *Service) SetMFA(m MFAEnroller) { s.mfa = m }

// RegistrationPolicy is the part of the auth-policy service this package needs:
// the per-tenant self-registration switch and the password check run wherever a
// password is set. A tenantID of uuid.Nil means the platform baseline.
// Satisfied by *authpolicy.Service.
type RegistrationPolicy interface {
	SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
	ValidateForTenant(ctx context.Context, tenantID uuid.UUID, email, pw string) error
}

// SetRegistrationPolicy wires the hosted self-registration gate + password
// policy.
func (s *Service) SetRegistrationPolicy(p RegistrationPolicy) { s.regPolicy = p }

// MethodPolicy is the slice of the authentication policy that decides whether
// an organisation allows password sign-in. Satisfied by *authpolicy.Service.
type MethodPolicy interface {
	PasswordEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// SetMethodPolicy wires the sign-in method policy (nil = every method allowed).
func (s *Service) SetMethodPolicy(p MethodPolicy) { s.methods = p }

// AnomalyRecorder receives security signals from sign-in: each account lock and
// each network throttled for password spraying. Satisfied by *threat.Service.
type AnomalyRecorder interface {
	OnAccountLocked(ctx context.Context, lock AccountLock)
	OnSourceThrottled(ctx context.Context, throttle SourceThrottle)
}

// SetAnomalyRecorder wires the security-anomaly recorder.
func (s *Service) SetAnomalyRecorder(a AnomalyRecorder) { s.anomaly = a }

// DevicePolicy reports whether a tenant has opted into adaptive MFA (skipping
// the second factor on a trusted device). Satisfied by *authpolicy.Service;
// kept as an interface so auth doesn't import authpolicy.
type DevicePolicy interface {
	RememberDeviceEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
	// RememberDevicePolicy adds how long a device the tenant remembers stays
	// remembered.
	RememberDevicePolicy(ctx context.Context, tenantID uuid.UUID) (bool, time.Duration, error)
}

// SetDevicePolicy wires the adaptive-MFA (trusted-device) gate.
func (s *Service) SetDevicePolicy(d DevicePolicy) { s.devicePolicy = d }

// RiskAssessor checks whether the risk level of an auth request should force
// MFA even on a trusted device. Satisfied by *risk.Service
// (threat-detection/risk); kept as an interface so auth doesn't import that
// package.
type RiskAssessor interface {
	// ShouldForceMFA reports whether the request's risk score exceeds the tenant's
	// force-MFA threshold. country is an ISO code, or empty when unknown. It fails
	// open (false) on any error.
	ShouldForceMFA(ctx context.Context, tenantID, userID uuid.UUID, ip, ua, country string) bool
	// RecordSignIn remembers a sign-in that got its session, as later
	// assessments' history.
	RecordSignIn(ctx context.Context, tenantID, userID uuid.UUID, ua, country string)
}

// SetRiskAssessor wires the sign-in risk assessment.
func (s *Service) SetRiskAssessor(r RiskAssessor) { s.riskAssessor = r }

// SetSender wires the email sender for risk confirmation codes.
func (s *Service) SetSender(n notifier.Sender) { s.sender = n }

// LoginHook is a policy gate run after the credentials are verified. A non-nil
// error refuses the sign-in; otherwise the returned map (possibly nil) holds
// custom claims for the access token.
type LoginHook interface {
	Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error)
}

// SetLoginHook wires the post-credential Actions/Hooks gate.
func (s *Service) SetLoginHook(h LoginHook) { s.loginHook = h }

// LoginResult is either a full token pair (no MFA needed) or a pending MFA
// challenge that must be completed via CompleteMFALogin before tokens issue.
type LoginResult struct {
	Pair *TokenPair
	MFAChallenge
}

// MFAChallenge is a sign-in's pending second-factor challenge, when
// MFARequired is set.
type MFAChallenge struct {
	MFARequired bool
	MFAToken    string
	Methods     []string
	// Factors are the second factors the challenge can be met with.
	Factors []LoginFactor
	// EnrollmentRequired: the account must have a second factor and holds
	// none, so the challenge is met by setting up an authenticator app.
	// EnrollmentDueAt, when set, is when the organisation's grace period
	// ends; until then the setup may be skipped. See mfapolicy.go.
	EnrollmentRequired bool
	EnrollmentDueAt    *time.Time
}

// LoginSessionResult is the hosted-login (cookie) analogue of LoginResult:
// either a ready SSO session (RawCookie set, to be written via
// SetLoginSessionCookie) or a pending MFA challenge to complete via
// CompleteMFALoginSession before the cookie is issued.
type LoginSessionResult struct {
	UserID    uuid.UUID
	RawCookie string
	MFAChallenge
}

// TokenPair is a signed-in session: an access token, the refresh token that
// renews it, and when the session ends.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
	// SessionExpiresAt is when the session ends however active it is, and
	// IdleExpiresAt when it ends unless renewed before then, so a client can
	// warn its user ahead of either. The server refuses the session after
	// them whatever the client does.
	SessionExpiresAt time.Time `json:"session_expires_at"`
	IdleExpiresAt    time.Time `json:"idle_expires_at"`
	SessionID        uuid.UUID `json:"session_id"`
	UserID           uuid.UUID `json:"user_id"`
	// Tenant the token is scoped to; nil/omitted for a tenant-less session.
	TenantID *uuid.UUID `json:"tenant_id,omitempty"`
}
