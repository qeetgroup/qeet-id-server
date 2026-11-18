// Package auth handles login, refresh, logout, and session storage.
// Access & ID tokens are signed ES256 or RS256, by the signing key's type, and
// verifiable via the public JWKS; see internal/platform/crypto/tokens.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service signs people in, by every method, and manages their sessions and
// refresh tokens. Each dependency is required and set once, by New, so no
// sign-in check depends on a wiring call having been made.
type Service struct {
	pool              *pgxpool.Pool
	q                 *dbgen.Queries
	users             *user.Repository
	tokens            *tokens.Issuer
	mfa               MFAEnroller
	memberPermissions []string
	regPolicy         RegistrationPolicy
	methods           MethodPolicy
	capture           DomainCapture
	anomaly           AnomalyRecorder
	devicePolicy      DevicePolicy
	riskAssessor      RiskAssessor
	sender            notifier.Sender
	loginHook         LoginHook
	addresses         ipallow.AddressPolicy
	signOutNotifier   SignOutNotifier
	signals           *sessionsignal.Signaller
	// lockout is the platform-wide sign-in lockout configuration, and
	// lockoutSource the per-organization settings. See lockout.go.
	lockout       LockoutConfig
	lockoutSource LockoutSource
	// sessionMaxAge and sessionIdle bound a session whose organization sets
	// no bounds of its own (zero = the platform defaults). See lifetime.go.
	sessionMaxAge time.Duration
	sessionIdle   time.Duration
	// uses throttles the record of sessions' use; see SessionUsed.
	uses sessionUses
	// failures bounds the record of failed sign-ins; see signinaudit.go.
	failures failureBound
	// refreshGrace is how long a rotated refresh token gets its rotation's
	// pair again, kept sealed with refreshCipher (zero = never). See
	// refreshretry.go.
	refreshGrace  time.Duration
	refreshCipher *envelope.Cipher
}

// Deps are what the sign-in service is built from. Every field is required
// except the last four, which are settings with a default.
type Deps struct {
	Pool   *pgxpool.Pool
	Users  *user.Repository
	Tokens *tokens.Issuer
	Cipher *envelope.Cipher // seals the pair a refresh rotation keeps
	// MFA gates a sign-in on a second factor; Risk assesses every sign-in.
	MFA  MFAEnroller
	Risk RiskAssessor
	// Registration, Methods, Devices and Lockout are the organization's
	// authentication policy: self-registration and the password check, the
	// methods it allows, remembered devices and sign-in lockout.
	Registration RegistrationPolicy
	Methods      MethodPolicy
	Devices      DevicePolicy
	Lockout      LockoutSource
	Capture      DomainCapture         // sends a captured address to its identity provider
	Addresses    ipallow.AddressPolicy // asked before a session is issued or renewed
	Anomalies    AnomalyRecorder       // receives account locks and spraying sources
	Sender       notifier.Sender       // emails risk confirmation codes and lock notices
	LoginHook    LoginHook             // an organization's post-credential policy gate
	SignOut      SignOutNotifier       // tells applications of a hosted sign-out
	Signals      *sessionsignal.Signaller
	// MemberPermissions are all a member may hold without counting as an
	// administrator for an admin_only second-factor requirement (nil: every
	// permission counts, the stricter reading).
	MemberPermissions []string
	// SessionMaxAge and SessionIdle bound a session whose organization sets
	// none (zero: the platform defaults).
	SessionMaxAge time.Duration
	SessionIdle   time.Duration
	// RefreshReuseGrace is how long a rotated refresh token sent again gets
	// its rotation's pair (zero: never). See refreshretry.go.
	RefreshReuseGrace time.Duration
}

// New returns the sign-in and session service built from d, or an error
// naming the first required dependency d lacks.
func New(d Deps) (*Service, error) {
	for _, dep := range []struct {
		name    string
		missing bool
	}{
		{"Pool", d.Pool == nil}, {"Users", d.Users == nil}, {"Tokens", d.Tokens == nil},
		{"Cipher", d.Cipher == nil}, {"MFA", d.MFA == nil}, {"Risk", d.Risk == nil},
		{"Registration", d.Registration == nil}, {"Methods", d.Methods == nil},
		{"Devices", d.Devices == nil}, {"Lockout", d.Lockout == nil}, {"Capture", d.Capture == nil},
		{"Addresses", d.Addresses == nil}, {"Anomalies", d.Anomalies == nil}, {"Sender", d.Sender == nil},
		{"LoginHook", d.LoginHook == nil}, {"SignOut", d.SignOut == nil}, {"Signals", d.Signals == nil},
	} {
		if dep.missing {
			return nil, fmt.Errorf("auth: the sign-in service needs %s", dep.name)
		}
	}
	return &Service{
		pool: d.Pool, q: dbgen.New(d.Pool), users: d.Users, tokens: d.Tokens,
		mfa: d.MFA, riskAssessor: d.Risk, regPolicy: d.Registration, methods: d.Methods,
		devicePolicy: d.Devices, lockoutSource: d.Lockout, capture: d.Capture, addresses: d.Addresses,
		anomaly: d.Anomalies, sender: d.Sender, loginHook: d.LoginHook, signOutNotifier: d.SignOut,
		signals: d.Signals, memberPermissions: d.MemberPermissions,
		sessionMaxAge: d.SessionMaxAge, sessionIdle: d.SessionIdle,
		refreshGrace: d.RefreshReuseGrace, refreshCipher: d.Cipher,
		lockout: DefaultLockoutConfig(), failures: newFailureBound(),
	}, nil
}

// LoginPush is a push approval request sent for a sign-in: its id, when it
// expires, and the number shown on the sign-in screen for the phone to match.
type LoginPush struct {
	ID        uuid.UUID
	ExpiresAt time.Time
	Number    int
}

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
	// factors for a sign-in to organizationID (nil: none).
	SendLoginCode(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, factorID uuid.UUID) error
	// BeginLoginPasskey starts a passkey assertion for the user's own
	// passkeys; FinishLoginPasskeyTx verifies one inside the challenge
	// transaction (a domain error: not verified).
	BeginLoginPasskey(ctx context.Context, userID uuid.UUID) (uuid.UUID, any, error)
	FinishLoginPasskeyTx(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, credential json.RawMessage) error
	// StartLoginPush sends a push approval request to the user's devices and
	// returns it; LoginPushStatusTx reads its state ("pending", "approved",
	// "denied" or "expired") under lock.
	StartLoginPush(ctx context.Context, userID uuid.UUID, ip, ua string) (LoginPush, error)
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

// RegistrationPolicy is the part of the auth-policy service this package needs:
// the per-organization self-registration switch and the password check run wherever a
// password is set. An organizationID of uuid.Nil means the platform baseline.
// Satisfied by *authpolicy.Service.
type RegistrationPolicy interface {
	SelfRegistrationEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
	ValidateForOrganization(ctx context.Context, organizationID uuid.UUID, email, pw string) error
}

// MethodPolicy is the slice of the authentication policy that decides whether
// an organization allows password sign-in. Satisfied by *authpolicy.Service.
type MethodPolicy interface {
	PasswordEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
}

// AnomalyRecorder receives security signals from sign-in: each account lock and
// each network throttled for password spraying. Satisfied by *threat.Service.
type AnomalyRecorder interface {
	OnAccountLocked(ctx context.Context, lock AccountLock)
	OnSourceThrottled(ctx context.Context, throttle SourceThrottle)
}

// DevicePolicy reports whether an organization has opted into adaptive MFA (skipping
// the second factor on a trusted device). Satisfied by *authpolicy.Service;
// kept as an interface so auth doesn't import authpolicy.
type DevicePolicy interface {
	RememberDeviceEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
	// RememberDevicePolicy adds how long a device the organization remembers stays
	// remembered.
	RememberDevicePolicy(ctx context.Context, organizationID uuid.UUID) (bool, time.Duration, error)
}

// RiskAssessor checks whether the risk level of an auth request should force
// MFA even on a trusted device. Satisfied by *risk.Service
// (threat-detection/risk); kept as an interface so auth doesn't import that
// package.
type RiskAssessor interface {
	// ShouldForceMFA reports whether the request's risk score exceeds the organization's
	// force-MFA threshold. country is an ISO code, or empty when unknown. It fails
	// open (false) on any error.
	ShouldForceMFA(ctx context.Context, organizationID, userID uuid.UUID, ip, ua, country string) bool
	// RecordSignIn remembers a sign-in that got its session, as later
	// assessments' history.
	RecordSignIn(ctx context.Context, organizationID, userID uuid.UUID, ua, country string)
}

// LoginHook is a policy gate run after the credentials are verified. A non-nil
// error refuses the sign-in; otherwise the returned map (possibly nil) holds
// custom claims for the access token.
type LoginHook interface {
	Run(ctx context.Context, organizationID, userID uuid.UUID, email string) (map[string]any, error)
}

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
	// EnrollmentDueAt, when set, is when the organization's grace period
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
	// Organization the token is scoped to; nil/omitted for an organization-less session.
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
}
