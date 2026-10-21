// Package auth handles login, refresh, logout, and session storage.
// Access & ID tokens are signed with ES256 (asymmetric) and verifiable via the
// public JWKS; see internal/platform/tokens.
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/useragent"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

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
}

func NewService(pool *pgxpool.Pool, users *user.Repository, t *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), users: users, tokens: t, lockout: DefaultLockoutConfig()}
}

// SetSessionSignals wires the announcement of ended sessions (session.revoked
// webhooks). Called from internal/bootstrap/dependencies.go.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// otherSessionsEnded turns RevokeOtherSessionsForUser's rows into signals.
func otherSessionsEnded(userID uuid.UUID, rows []dbgen.RevokeOtherSessionsForUserRow) []sessionsignal.Session {
	ids, tenants := make([]uuid.UUID, len(rows)), make([]pgtype.UUID, len(rows))
	for i, r := range rows {
		ids[i], tenants[i] = r.ID, r.TenantID
	}
	return endedSessions(userID, ids, tenants)
}

// endedSessions turns the sessions a revocation query returned into signals.
func endedSessions(userID uuid.UUID, ids []uuid.UUID, tenants []pgtype.UUID) []sessionsignal.Session {
	out := make([]sessionsignal.Session, len(ids))
	for i, id := range ids {
		out[i] = sessionsignal.Session{ID: id, UserID: userID}
		if tenants[i].Valid {
			out[i].TenantID = uuid.UUID(tenants[i].Bytes)
		}
	}
	return out
}

// MFAEnroller is the slice of the MFA service the auth package needs to enforce
// a second factor at login. Wired in internal/bootstrap/dependencies.go via SetMFA.
type MFAEnroller interface {
	// LoginFactors lists the second factors the user can meet a sign-in
	// challenge with (none: sign in without one). See mfalogin.go.
	LoginFactors(ctx context.Context, userID uuid.UUID) ([]LoginFactor, error)
	// VerifyForLoginTx verifies an authenticator-app, recovery or email/SMS
	// code inside the challenge transaction so the code's consumption and the
	// challenge's commit together, and returns which kind met it ("totp",
	// "recovery_code" or "otp"); ("", nil) means the code was wrong, a non-nil
	// error is infrastructure.
	VerifyForLoginTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (string, error)
	// SendLoginCode sends a code to one of the user's confirmed email/SMS
	// factors for a sign-in to tenantID (nil: none).
	SendLoginCode(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, factorID uuid.UUID) error
	// BeginLoginPasskey starts a passkey assertion for the user's own
	// passkeys; FinishLoginPasskey verifies one (a domain error: not verified).
	BeginLoginPasskey(ctx context.Context, userID uuid.UUID) (uuid.UUID, any, error)
	FinishLoginPasskey(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage) error
	// StartLoginPush sends a push approval request to the user's devices and
	// returns its id and expiry; LoginPushStatusTx reads its state
	// ("pending", "approved", "denied" or "expired") under lock.
	StartLoginPush(ctx context.Context, userID uuid.UUID, ip, ua string) (uuid.UUID, time.Time, error)
	LoginPushStatusTx(ctx context.Context, tx pgx.Tx, userID, challengeID uuid.UUID) (string, error)
	// RecordVerification records that one of the user's sessions met a second
	// factor, stepping that session (and no other) up.
	RecordVerification(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, method string) error
	// StartLoginEnrollment starts an authenticator app for a sign-in's
	// enrolment challenge and returns its secret and provisioning URL;
	// ConfirmLoginEnrollment confirms it with a code from the app and returns
	// the account's new recovery codes ((nil, false, nil): a wrong code). Both
	// run inside the challenge transaction. See mfapolicy.go.
	StartLoginEnrollment(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (string, string, error)
	ConfirmLoginEnrollment(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, bool, error)
}

// SetMFA wires the MFA-at-login checker. Called from internal/bootstrap/dependencies.go.
func (s *Service) SetMFA(m MFAEnroller) { s.mfa = m }

// RegistrationPolicy is the slice of the auth-policy service the auth package
// needs: the per-tenant self-registration gate, and the one password check
// every path that sets a password runs — the rules of the organisation the
// account belongs to (uuid.Nil = none: the platform baseline), the offline
// strength baseline and, when enabled, the breach check. Satisfied by
// *authpolicy.Service. Wired in internal/bootstrap/dependencies.go via SetRegistrationPolicy.
type RegistrationPolicy interface {
	SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
	ValidateForTenant(ctx context.Context, tenantID uuid.UUID, email, pw string) error
}

// SetRegistrationPolicy wires the hosted self-registration gate + password
// policy. Called from internal/bootstrap/dependencies.go.
func (s *Service) SetRegistrationPolicy(p RegistrationPolicy) { s.regPolicy = p }

// MethodPolicy is the slice of the authentication policy that decides whether
// an organisation allows password sign-in. Satisfied by *authpolicy.Service.
type MethodPolicy interface {
	PasswordEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// SetMethodPolicy wires the sign-in method policy (nil = every method allowed).
// Called from internal/bootstrap/dependencies.go.
func (s *Service) SetMethodPolicy(p MethodPolicy) { s.methods = p }

// passwordAllowed refuses with ErrAuthMethodDisabled when tenantID has switched
// password sign-in off. uuid.Nil (no organisation) is not restricted.
func (s *Service) passwordAllowed(ctx context.Context, tenantID uuid.UUID) error {
	if tenantID == uuid.Nil || s.methods == nil {
		return nil
	}
	enabled, err := s.methods.PasswordEnabled(ctx, tenantID)
	if err != nil {
		return err
	}
	if !enabled {
		return errs.ErrAuthMethodDisabled
	}
	return nil
}

// checkNewPassword runs the password check for an account in tenantID
// (uuid.Nil = no organisation). With no policy wired it refuses rather than
// store a password nothing has checked.
func (s *Service) checkNewPassword(ctx context.Context, tenantID uuid.UUID, email, plain string) error {
	if s.regPolicy == nil {
		return errs.ErrNotImplemented
	}
	return s.regPolicy.ValidateForTenant(ctx, tenantID, email, plain)
}

// SelfRegistrationEnabled reports whether tenantID allows hosted self-service
// signup. Exposed so other access-domain services (e.g. the passkey-first
// signup ceremony) can gate on the same policy without duplicating it or
// requiring a password to validate. false, nil when no policy is wired.
func (s *Service) SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	if s.regPolicy == nil {
		return false, nil
	}
	return s.regPolicy.SelfRegistrationEnabled(ctx, tenantID)
}

// AnomalyRecorder receives security signals from the auth flow (nil = recording
// off): once for each sign-in lock, from the failure that set it, and once for
// each source network throttled for spraying (see lockout.go). Kept as an
// interface so auth doesn't import the threat package; satisfied by
// *threat.Service. Wired via SetAnomalyRecorder.
type AnomalyRecorder interface {
	OnAccountLocked(ctx context.Context, lock AccountLock)
	OnSourceThrottled(ctx context.Context, throttle SourceThrottle)
}

// SetAnomalyRecorder wires the security-anomaly recorder. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetAnomalyRecorder(a AnomalyRecorder) { s.anomaly = a }

// DevicePolicy reports whether a tenant has opted into adaptive MFA (skipping
// the second factor on a trusted device). Satisfied by *authpolicy.Service;
// kept as an interface so auth doesn't import authpolicy. Wired via
// SetDevicePolicy.
type DevicePolicy interface {
	RememberDeviceEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
	// RememberDevicePolicy adds how long a device the tenant remembers stays
	// remembered.
	RememberDevicePolicy(ctx context.Context, tenantID uuid.UUID) (bool, time.Duration, error)
}

// SetDevicePolicy wires the adaptive-MFA (trusted-device) gate. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetDevicePolicy(d DevicePolicy) { s.devicePolicy = d }

// RiskAssessor checks whether the risk level of an auth request should force
// MFA even on a trusted device. Satisfied by *risk.Service (threat-detection/risk);
// kept as an interface so auth doesn't import that package. Wired via SetRiskAssessor.
type RiskAssessor interface {
	// ShouldForceMFA returns true when the request's risk score — bot-likeness,
	// plus impossible-travel and device-reputation signals when a tenant has
	// opted into them — exceeds the tenant's configured force-MFA threshold.
	// country is a best-effort ISO code (empty when unresolved); fails open
	// (false) on any error.
	ShouldForceMFA(ctx context.Context, tenantID, userID uuid.UUID, ip, ua, country string) bool
}

// SetRiskAssessor wires the sign-in risk assessment. Called from internal/bootstrap/dependencies.go.
func (s *Service) SetRiskAssessor(r RiskAssessor) { s.riskAssessor = r }

// SetSender wires the email sender for risk confirmation codes. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetSender(n notifier.Sender) { s.sender = n }

// LoginHook is a synchronous policy gate run after credentials verify: it
// returns a non-nil error to DENY the sign-in, or nil to allow — in which case
// the returned map (possibly nil) carries custom claims to inject into the
// issued access token. nil hook = no gate. Satisfied by *authhook.Service; an
// interface so auth doesn't import it.
type LoginHook interface {
	Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error)
}

// SetLoginHook wires the post-credential Actions/Hooks gate. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetLoginHook(h LoginHook) { s.loginHook = h }

// mfaChallengeTTL bounds how long a pending second-factor login stays valid.
const mfaChallengeTTL = 10 * time.Minute

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

type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

// SignInAttempt is one password sign-in as the API received it.
type SignInAttempt struct {
	Email    string
	Password string
	// IP is the client IP as httpx.ClientIP derives it; its network keys the
	// lockout counters. "" when unknown.
	IP string
	// ClientID is the OAuth client a hosted login is serving ("" = none). Its
	// tenant's lockout settings apply (see SignInTenant).
	ClientID string
}

type SignupInput struct {
	Email       string
	Password    string
	DisplayName string
	IP          string
	UserAgent   string
}

// RefreshInput carries the rotation request plus client context used for
// auditing and theft-alert payloads. Callers that don't have IP/UA can
// leave them empty.
type RefreshInput struct {
	RefreshToken string
	IP           string
	UserAgent    string
	RequestID    string
}

// TenantBrief is the small tenant projection returned alongside Signup.
type TenantBrief struct {
	ID     uuid.UUID `json:"id"`
	Slug   string    `json:"slug"`
	Name   string    `json:"name"`
	Plan   string    `json:"plan"`
	Region string    `json:"region"`
}

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

// Signup creates a tenant-less identity (user + password + session) and logs them in; no tenant or role is created.
func (s *Service) Signup(ctx context.Context, in SignupInput) (*TokenPair, *user.User, *TenantBrief, error) {
	// The account belongs to no organisation, so the platform baseline applies.
	if err := s.checkNewPassword(ctx, uuid.Nil, in.Email, in.Password); err != nil {
		return nil, nil, nil, err
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback(ctx)

	// 1) User — tenant-less (tenant_id NULL).
	u := &user.User{Email: strings.TrimSpace(in.Email), Status: "active", Metadata: map[string]any{}}
	if in.DisplayName != "" {
		dn := in.DisplayName
		u.DisplayName = &dn
	}
	urow, err := s.q.WithTx(tx).InsertTenantlessUser(ctx, dbgen.InsertTenantlessUserParams{
		Email:       u.Email,
		DisplayName: u.DisplayName,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, nil, nil, errs.ErrAuthEmailExists
		}
		return nil, nil, nil, err
	}
	u.ID, u.CreatedAt, u.UpdatedAt = urow.ID, urow.CreatedAt, urow.UpdatedAt

	// 2) Password credential.
	if err := s.q.WithTx(tx).InsertPasswordCredential(ctx, dbgen.InsertPasswordCredentialParams{
		UserID:       u.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, nil, nil, err
	}

	// 3) Tenant-less session + access + refresh token, all in the same tx so
	// signup is fully atomic.
	sessionID := uuid.New()
	maxAge, idle := s.sessionDefaults()
	bounds, err := s.q.WithTx(tx).InsertTenantlessSession(ctx, dbgen.InsertTenantlessSessionParams{
		ID:            sessionID,
		UserID:        u.ID,
		Ip:            in.IP,
		UserAgent:     &in.UserAgent,
		MaxAgeSeconds: maxAge.Seconds(),
		IdleSeconds:   idle.Seconds(),
		Country:       httpx.GeoCountry(ctx),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	access, exp, err := s.tokens.IssueSessionAccess(u.ID, uuid.Nil, sessionID, nil, bounds.ExpiresAt)
	if err != nil {
		return nil, nil, nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: refreshHash,
		ExpiresAt: s.refreshExpiry(bounds.ExpiresAt),
	}); err != nil {
		return nil, nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, nil, err
	}

	return &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     refreshRaw,
		SessionExpiresAt: bounds.ExpiresAt,
		IdleExpiresAt:    bounds.IdleExpiresAt,
		SessionID:        sessionID,
		UserID:           u.ID,
	}, u, nil, nil
}

// SwitchTenantInput names who switches, from which of their sessions, and to
// which organization. FromSessionID must come from the caller's own access
// token, never from anything the client supplies.
type SwitchTenantInput struct {
	UserID        uuid.UUID
	FromSessionID uuid.UUID
	TenantID      uuid.UUID
	IP            string
	UserAgent     string
}

// SwitchTenant replaces the caller's session with one scoped to another
// organization they belong to. The new session's token carries the claims that
// organization's authentication hook adds (the hook may also refuse the
// switch), and keeps them across renewals. The session switched from ends —
// superseded by the new one, its refresh token refused — in the same
// transaction, and revocation subscribers of the organization it belonged to
// are told, with "tenant_switch" as the reason.
//
// The organization's second-factor requirement applies to entering it, not
// only to signing in at home: the sign-in behind the session
// switched from must have met a factor, or that session must hold a fresh
// step-up, and the new session carries it on.
//
// Refused with ErrAuthNotTenantMember for an organization the caller does not
// belong to, with ErrStepUpRequired or ErrMFAEnrollmentRequired while its
// second-factor requirement isn't met (see tenantFactorShortfall), with the
// hook's error when the hook refuses, and with ErrUnauthorized when the
// session switched from has already ended (its access token outlives it by a
// few minutes); in every refusal nothing changes.
func (s *Service) SwitchTenant(ctx context.Context, in SwitchTenantInput) (*TokenPair, error) {
	member, err := s.q.CheckTenantMembership(ctx, dbgen.CheckTenantMembershipParams{
		UserID:   in.UserID,
		TenantID: in.TenantID,
	})
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, errs.ErrAuthNotTenantMember
	}
	// Cheap check before calling out to the hook; the supersede below is the
	// authoritative one.
	live, err := s.q.IsSessionLiveForUser(ctx, dbgen.IsSessionLiveForUserParams{SessionID: in.FromSessionID, UserID: in.UserID})
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errs.ErrUnauthorized
	}
	carried, err := s.carriedSecondFactor(ctx, in.FromSessionID, in.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.tenantFactorShortfall(ctx, in.UserID, in.TenantID, carried); err != nil {
		return nil, err
	}
	var claims map[string]any
	if s.loginHook != nil {
		u, err := s.users.Get(ctx, in.UserID)
		if err != nil {
			return nil, err
		}
		if claims, err = s.loginHook.Run(ctx, in.TenantID, in.UserID, u.Email); err != nil {
			return nil, err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	// The user row first, in the order every bulk session revocation takes it.
	if _, err := q.LockUserForSessionRevocation(ctx, in.UserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized
		}
		return nil, err
	}
	// The same sign-in, so the new session ends when this one would have.
	ends, err := q.SessionEnd(ctx, dbgen.SessionEndParams{SessionID: in.FromSessionID, UserID: in.UserID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	pair, err := s.issuePairTx(ctx, tx, in.UserID, in.TenantID, in.IP, in.UserAgent, "tenant_switch", claims,
		map[string]any{"previous_session_id": in.FromSessionID, "second_factor": carried}, ends)
	if err != nil {
		return nil, err
	}
	if err := carrySecondFactor(ctx, tx, pair.SessionID, carried); err != nil {
		return nil, err
	}
	left, err := q.SupersedeSession(ctx, dbgen.SupersedeSessionParams{
		NewSessionID: pgtype.UUID{Bytes: pair.SessionID, Valid: true},
		SessionID:    in.FromSessionID,
		UserID:       in.UserID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonTenantSwitch,
		endedSessions(in.UserID, []uuid.UUID{in.FromSessionID}, []pgtype.UUID{left})...)
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// SignInInvitedAccount signs in an account an accepted invitation has just
// created in tenantID, as at sign-up: where the organisation requires a second
// factor the result is the enrolment challenge instead of a session.
func (s *Service) SignInInvitedAccount(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*LoginResult, error) {
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if gate.challenged() {
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, nil, gate, firstFactorPassword, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePair(ctx, userID, tenantID, ip, ua, "invite_accept")
	if err != nil {
		return nil, err
	}
	return &LoginResult{Pair: pair}, nil
}

// EnterInvitedTenant issues the session an existing account enters tenantID
// with after accepting its invitation while signed in. fromSessionID is the
// caller's session (uuid.Nil: none, so no factor carries): its second factor
// carries on as for SwitchTenant, and the entry is refused the same way
// (ErrStepUpRequired, ErrMFAEnrollmentRequired) while the organisation
// requires one it didn't meet. The invitation stays accepted, so
// the caller can step up or set a factor up and switch in.
func (s *Service) EnterInvitedTenant(ctx context.Context, userID, tenantID, fromSessionID uuid.UUID, ip, ua string) (*TokenPair, error) {
	carried := ""
	if fromSessionID != uuid.Nil {
		var err error
		if carried, err = s.carriedSecondFactor(ctx, fromSessionID, userID); err != nil {
			return nil, err
		}
	}
	if err := s.tenantFactorShortfall(ctx, userID, tenantID, carried); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, userID, tenantID, ip, ua, "invite_accept", nil,
		map[string]any{"previous_session_id": fromSessionID, "second_factor": carried}, time.Time{})
	if err != nil {
		return nil, err
	}
	if err := carrySecondFactor(ctx, tx, pair.SessionID, carried); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// carriedSecondFactor is the second factor a session's sign-in met, for a
// session opened from it to carry on: the sign-in's own, else "step_up" while
// the session holds a fresh step-up, else "". ErrUnauthorized when the session
// isn't the user's or has ended.
func (s *Service) carriedSecondFactor(ctx context.Context, sessionID, userID uuid.UUID) (string, error) {
	row, err := s.q.SessionSecondFactor(ctx, dbgen.SessionSecondFactorParams{SessionID: sessionID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrUnauthorized
	}
	if err != nil {
		return "", err
	}
	switch {
	case row.SecondFactor != "":
		return row.SecondFactor, nil
	case row.SteppedUp:
		return secondFactorStepUp, nil
	}
	return "", nil
}

// carrySecondFactor records on a session opened from another the second
// factor carried from it ("": none, nothing to record).
func carrySecondFactor(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, factor string) error {
	if factor == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE auth.sessions SET second_factor = $2 WHERE id = $1`, sessionID, factor)
	return err
}

// Login verifies the password and, when the account holds a second factor or
// must have one (see mfapolicy.go), returns an MFA challenge instead of tokens
// (complete it via CompleteMFALoginWith). Otherwise it returns a full token
// pair.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	u, claims, err := s.CheckPassword(ctx, SignInAttempt{Email: in.Email, Password: in.Password, IP: in.IP})
	if err != nil {
		return nil, err
	}
	gate, err := s.mfaGate(ctx, u.ID, u.TenantID)
	if err != nil {
		return nil, err
	}
	switch s.nextSignInStep(ctx, u.ID, u.TenantID, gate, firstFactorPassword, "", in.IP, in.UserAgent, httpx.GeoCountry(ctx)) {
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, u.ID, u.TenantID, claims, gate, firstFactorPassword, in.IP, in.UserAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, u.ID, u.TenantID, claims, firstFactorPassword, in.IP, in.UserAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePairWithClaims(ctx, u.ID, u.TenantID, in.IP, in.UserAgent, "password", claims)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Pair: pair}, nil
}

// BeginLoginSession is the hosted-login (cookie) equivalent of Login: it
// verifies the password and, when the account holds a second factor or must
// have one, returns an MFA challenge instead of an SSO session (complete it
// via CompleteMFALoginSessionWith). Otherwise it mints the SSO session cookie
// value. Without this check the cookie flow would bypass MFA that the token
// flow enforces.
func (s *Service) BeginLoginSession(ctx context.Context, in SignInAttempt, ua, trustedToken, country string) (*LoginSessionResult, error) {
	// Hook-issued claims aren't threaded into the hosted-login cookie flow: the
	// SSO cookie is opaque, and any JWT is minted later by the OIDC authorize
	// flow for a specific client, decoupled from this call — a separate,
	// larger integration than the direct API-token login this powers.
	// The hosted login opens a session for the browser, not for one
	// organisation; the application it is serving belongs to one, whose address
	// rules refuse here, not later at authorize. Before the password is
	// checked, so the answer is the same whether it is right or wrong.
	clientTenant, err := s.SignInTenant(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	if err := s.checkAddress(ctx, clientTenant, uuid.Nil, in.IP, "hosted_password"); err != nil {
		return nil, err
	}
	u, _, err := s.CheckPassword(ctx, in)
	if err != nil {
		return nil, err
	}
	// The organisation of the application served requires its second factor
	// here as well as the account's own.
	gate, err := s.mfaGateFor(ctx, u.ID, u.TenantID, clientTenant)
	if err != nil {
		return nil, err
	}
	// A trusted device may skip a factor the account holds, never the setting
	// up of one it must have, and never on a risky sign-in.
	switch s.nextSignInStep(ctx, u.ID, u.TenantID, gate, firstFactorPassword, trustedToken, in.IP, ua, country) {
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, u.ID, u.TenantID, nil, firstFactorPassword, in.IP, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: u.ID, MFAChallenge: challenge}, nil
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, u.ID, u.TenantID, nil, gate, firstFactorPassword, in.IP, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: u.ID, MFAChallenge: challenge}, nil
	}
	raw, err := s.createLoginSession(ctx, u.ID, in.IP, ua, gate.skippedFactor())
	if err != nil {
		return nil, err
	}
	return &LoginSessionResult{UserID: u.ID, RawCookie: raw}, nil
}

// RegisterInTenant creates a new end-user in the given tenant from the hosted
// signup flow and signs them in by minting the SSO session cookie value. It is
// gated by the tenant's self_registration_enabled policy and checks the
// password against that tenant's rules (see RegistrationPolicy). Returns
// the created user and either the raw cookie value to write via
// SetLoginSessionCookie or, when the organisation requires MFA, an enrolment
// challenge to meet first (see mfapolicy.go).
func (s *Service) RegisterInTenant(ctx context.Context, tenantID uuid.UUID, email, plain, displayName, ip, ua string) (*user.User, *LoginSessionResult, error) {
	if s.regPolicy == nil {
		return nil, nil, errs.ErrNotImplemented
	}
	enabled, err := s.regPolicy.SelfRegistrationEnabled(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	if !enabled {
		return nil, nil, errs.ErrAuthSelfRegistrationDisabled
	}
	// Nobody joins an organisation from an address it doesn't allow.
	if err := s.checkAddress(ctx, tenantID, uuid.Nil, ip, "hosted_signup"); err != nil {
		return nil, nil, err
	}
	if err := s.checkNewPassword(ctx, tenantID, email, plain); err != nil {
		return nil, nil, err
	}
	hash, err := password.Hash(plain)
	if err != nil {
		return nil, nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	var dnArg any
	u := &user.User{Email: strings.TrimSpace(email), Status: "active", Metadata: map[string]any{}}
	if displayName != "" {
		dnArg = displayName
		dn := displayName
		u.DisplayName = &dn
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`, tenantID, u.Email, dnArg).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if pgxerr.IsUnique(err) {
			return nil, nil, errs.ErrAuthEmailExists
		}
		return nil, nil, err
	}
	if err := s.q.WithTx(tx).InsertPasswordCredential(ctx, dbgen.InsertPasswordCredentialParams{
		UserID:       u.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}

	// A new account holds no factor: where the organisation requires one, it
	// is set up before the first session. Its sign-in is still assessed, so
	// later ones have a device and country to compare against; there is no
	// verified address yet to confirm a risky one with.
	gate, err := s.mfaGate(ctx, u.ID, tenantID)
	if err != nil {
		return nil, nil, err
	}
	if s.nextSignInStep(ctx, u.ID, tenantID, gate, firstFactorPassword, "", ip, ua, httpx.GeoCountry(ctx)) == stepChallenge {
		challenge, err := s.challengeSignIn(ctx, u.ID, tenantID, nil, gate, firstFactorPassword, ip, ua)
		if err != nil {
			return nil, nil, err
		}
		return u, &LoginSessionResult{UserID: u.ID, MFAChallenge: challenge}, nil
	}
	raw, err := s.CreateLoginSession(ctx, u.ID, ip, ua)
	if err != nil {
		return nil, nil, err
	}
	return u, &LoginSessionResult{UserID: u.ID, RawCookie: raw}, nil
}

// How a challenged sign-in proved its first factor (mfa_login_challenges
// first_factor). The session it completes records the method
// "<first factor>_mfa", or the first factor alone when an enrolment was put
// off.
const (
	firstFactorPassword  = "password"
	firstFactorMagicLink = "magic_link"
	firstFactorSocial    = "social"
)

// challengeSignIn records a single-use, short-lived pending sign-in that
// CompleteMFALoginWith (or CompleteMFALoginSessionWith) later exchanges for a
// session, and audits why it was challenged. claims (nilable) are any
// Auth-Hook-issued custom claims to carry across the MFA step into the
// eventual access token.
func (s *Service) challengeSignIn(ctx context.Context, userID, tenantID uuid.UUID, claims map[string]any, gate mfaGate, firstFactor, ip, ua string) (MFAChallenge, error) {
	var tid any
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		tid = tenantID
		tenantPtr = &tenantID
	}
	var claimsArg any
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return MFAChallenge{}, err
		}
		claimsArg = raw
	}
	challenge := MFAChallenge{MFARequired: true, Methods: methodsOf(gate.factors), Factors: gate.factors}
	if gate.enrollment() {
		challenge.Methods = []string{"totp"}
		challenge.Factors = []LoginFactor{}
		challenge.EnrollmentRequired = true
		challenge.EnrollmentDueAt = gate.req.graceUntil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MFAChallenge{}, err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.mfa_login_challenges (user_id, tenant_id, expires_at, claims, enrollment, first_factor)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
	`, userID, tid, time.Now().UTC().Add(mfaChallengeTTL), claimsArg, challenge.EnrollmentRequired, firstFactor).Scan(&id); err != nil {
		return MFAChallenge{}, err
	}
	meta := map[string]any{"reason": gate.reason(), "enrollment": challenge.EnrollmentRequired, "methods": challenge.Methods,
		"first_factor": firstFactor}
	if challenge.EnrollmentDueAt != nil {
		meta["grace_until"] = challenge.EnrollmentDueAt
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       "auth.mfa_challenged",
		ResourceType: "user",
		ResourceID:   &userID,
		IP:           ip,
		UserAgent:    ua,
		Metadata:     meta,
	}); err != nil {
		return MFAChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MFAChallenge{}, err
	}
	challenge.MFAToken = id.String()
	return challenge, nil
}

// metChallenge is a sign-in challenge met and consumed.
type metChallenge struct {
	userID uuid.UUID
	// tenantID is uuid.Nil for a tenant-less challenge.
	tenantID uuid.UUID
	claims   map[string]any
	// recoveryCodes are minted when the challenge was met by setting up an
	// authenticator app; shown once.
	recoveryCodes []string
	// deferred: an enrolment challenge skipped in the grace period — no
	// factor was met.
	deferred bool
	// firstFactor is how the sign-in proved its first factor.
	firstFactor string
	// riskVerified: a risk challenge met by the code to the verified email —
	// confirmed, but no second factor was met.
	riskVerified bool
	// stepUpMethod is the second factor that met the challenge ("" when none
	// did): the session the sign-in opens starts stepped up by it.
	stepUpMethod string
}

// method is the sign-in method recorded on the session.
func (m metChallenge) method() string {
	switch {
	case m.deferred:
		return m.firstFactor
	case m.riskVerified:
		return m.firstFactor + "_email_confirmed"
	}
	return m.firstFactor + "_mfa"
}

// verifyAndConsumeMFAChallenge validates a pending MFA login challenge and the
// proof offered for it. On a valid proof it consumes (deletes) the challenge
// and returns the user, its tenant, and any claims stashed by challengeSignIn.
// A wrong proof is rejected WITHOUT consuming the challenge so the user can
// retry within the TTL. An enrolment challenge is met by the code that
// confirms the authenticator app started for it, or skipped while the grace
// period runs (see mfapolicy.go). Shared by the token flow
// (CompleteMFALoginWith) and the hosted cookie flow
// (CompleteMFALoginSessionWith).
func (s *Service) verifyAndConsumeMFAChallenge(ctx context.Context, mfaToken string, proof MFAProof) (metChallenge, error) {
	if s.mfa == nil {
		return metChallenge{}, errs.ErrNotImplemented
	}
	id, err := uuid.Parse(mfaToken)
	if err != nil {
		return metChallenge{}, errs.ErrAuthSessionInvalid
	}
	var userID uuid.UUID
	var tenantID *uuid.UUID
	var expiresAt time.Time
	var rawClaims []byte
	var challengeFailures int16
	var passkeySession, pushChallenge *uuid.UUID
	var enrollment, enrollmentStarted, riskEmail bool
	var firstFactor string
	var emailCodeHash *string
	var emailCodeExpires *time.Time
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return metChallenge{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		SELECT user_id, tenant_id, expires_at, claims, failed_attempts, passkey_session_id, push_challenge_id,
		       enrollment, enrollment_started, first_factor, risk_email, email_code_hash, email_code_expires_at
		FROM auth.mfa_login_challenges
		WHERE id = $1
		FOR UPDATE
	`, id).Scan(&userID, &tenantID, &expiresAt, &rawClaims, &challengeFailures, &passkeySession, &pushChallenge,
		&enrollment, &enrollmentStarted, &firstFactor, &riskEmail, &emailCodeHash, &emailCodeExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return metChallenge{}, errs.ErrAuthMFAChallengeExpired
	}
	if err != nil {
		return metChallenge{}, err
	}
	if time.Now().After(expiresAt) {
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
			return metChallenge{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return metChallenge{}, err
		}
		return metChallenge{}, errs.ErrAuthMFAChallengeExpired
	}
	met := metChallenge{userID: userID, firstFactor: firstFactor}
	if tenantID != nil {
		met.tenantID = *tenantID
	}
	if len(rawClaims) > 0 {
		_ = json.Unmarshal(rawClaims, &met.claims)
	}
	// What the challenge cannot be met with is refused before an attempt is
	// counted.
	switch {
	case (enrollment || riskEmail) && (proof.Passkey != nil || proof.Push):
		return metChallenge{}, errNotAFactorChallenge
	case riskEmail && proof.Skip:
		return metChallenge{}, errs.ErrBadRequest.WithDetail("This sign-in needs confirming; it cannot be skipped.")
	case enrollment && proof.Skip:
		return s.deferEnrollment(ctx, tx, id, met)
	case !enrollment && proof.Skip:
		return metChallenge{}, errs.ErrBadRequest.WithDetail("This sign-in needs a second factor; it cannot be skipped.")
	case enrollment && !enrollmentStarted:
		return metChallenge{}, errs.ErrMFAEnrollNotStarted
	case enrollment:
		if err := s.stillWithoutFactor(ctx, userID); err != nil {
			return metChallenge{}, err
		}
	}
	// An unanswered or expired push request is not a wrong answer: it costs
	// no attempt, and the challenge stays as it is.
	if proof.Push && pushChallenge != nil {
		status, err := s.mfa.LoginPushStatusTx(ctx, tx, userID, *pushChallenge)
		if err != nil {
			return metChallenge{}, err
		}
		switch status {
		case "pending":
			return metChallenge{}, errs.ErrMFAPushPending
		case "expired":
			return metChallenge{}, errs.ErrMFAPushChallengeExpired
		}
	}
	accountRemaining, err := reserveLoginMFAAttempt(ctx, tx, userID)
	if err != nil {
		return metChallenge{}, err
	}
	var ok bool
	if riskEmail {
		// Confirmed by the latest code sent to the verified email; no second
		// factor is met, so the session starts with no step-up.
		ok = emailCodeHash != nil && emailCodeExpires != nil && time.Now().Before(*emailCodeExpires) &&
			subtle.ConstantTimeCompare([]byte(*emailCodeHash), []byte(codes.Hash(strings.TrimSpace(proof.Code)))) == 1
		met.riskVerified = ok
	} else if enrollment {
		met.recoveryCodes, ok, err = s.mfa.ConfirmLoginEnrollment(ctx, tx, userID, proof.Code)
		if ok {
			met.stepUpMethod = "totp"
		}
	} else {
		met.stepUpMethod, err = s.verifyMFAProof(ctx, tx, userID, passkeySession, pushChallenge, proof)
		ok = met.stepUpMethod != ""
	}
	if err != nil {
		return metChallenge{}, err
	}
	if !ok {
		next := challengeFailures + 1
		remaining := maxMFALoginAttempts - int(next)
		if next >= maxMFALoginAttempts {
			if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
				return metChallenge{}, err
			}
		} else if _, err := tx.Exec(ctx, `
			UPDATE auth.mfa_login_challenges SET failed_attempts = $2 WHERE id = $1
		`, id, next); err != nil {
			return metChallenge{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return metChallenge{}, err
		}
		if remaining <= 0 || accountRemaining <= 0 {
			return metChallenge{}, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
		}
		if accountRemaining < remaining {
			remaining = accountRemaining
		}
		return metChallenge{}, errs.ErrMFACodeInvalid.WithMetadata(map[string]any{"remaining_attempts": remaining})
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
		return metChallenge{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND purpose = 'login'`, userID); err != nil {
		return metChallenge{}, err
	}
	if enrollment {
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID:     tenantID,
			ActorUserID:  &userID,
			ActorType:    "user",
			Action:       "mfa.totp_enrolled",
			ResourceType: "user",
			ResourceID:   &userID,
			Metadata:     map[string]any{"recovery_codes_minted": len(met.recoveryCodes), "via": "sign_in"},
		}); err != nil {
			return metChallenge{}, err
		}
	}
	// The sign-in met its second factor: recorded for both sign-in flows, so
	// the trail says which first factor it followed.
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       metAction(riskEmail),
		ResourceType: "user",
		ResourceID:   &userID,
		Metadata:     map[string]any{"first_factor": firstFactor, "proof": metProofKind(proof, enrollment, riskEmail)},
	}); err != nil {
		return metChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return metChallenge{}, err
	}
	return met, nil
}

// deferEnrollment consumes an enrolment challenge skipped while the grace
// period runs, and audits it. Refused (ErrMFAEnrollmentRequired) once the
// account must set up a factor now; refusing costs no attempt.
func (s *Service) deferEnrollment(ctx context.Context, tx pgx.Tx, id uuid.UUID, met metChallenge) (metChallenge, error) {
	graceUntil, err := s.mayDeferEnrollment(ctx, met.userID, met.tenantID)
	if err != nil {
		return metChallenge{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
		return metChallenge{}, err
	}
	var tenantPtr *uuid.UUID
	if met.tenantID != uuid.Nil {
		tenantPtr = &met.tenantID
	}
	meta := map[string]any{"first_factor": met.firstFactor}
	if graceUntil != nil {
		meta["grace_until"] = graceUntil
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &met.userID,
		ActorType:    "user",
		Action:       "auth.mfa_enrollment_deferred",
		ResourceType: "user",
		ResourceID:   &met.userID,
		Metadata:     meta,
	}); err != nil {
		return metChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return metChallenge{}, err
	}
	met.deferred = true
	return met, nil
}

const (
	maxMFALoginAttempts   = 5
	mfaLoginAttemptWindow = 10 * time.Minute
)

func reserveLoginMFAAttempt(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.mfa_attempt_budgets (user_id, purpose)
		VALUES ($1, 'login')
		ON CONFLICT DO NOTHING
	`, userID); err != nil {
		return 0, err
	}
	var failed int16
	var windowStarted time.Time
	var lockedUntil pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		SELECT failed_attempts, window_started_at, locked_until
		FROM auth.mfa_attempt_budgets
		WHERE user_id = $1 AND purpose = 'login'
		FOR UPDATE
	`, userID).Scan(&failed, &windowStarted, &lockedUntil); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		return 0, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if now.Sub(windowStarted) >= mfaLoginAttemptWindow || (lockedUntil.Valid && !now.Before(lockedUntil.Time)) {
		failed = 0
		windowStarted = now
	}
	next := failed + 1
	var lock any
	if next >= maxMFALoginAttempts {
		lock = now.Add(mfaLoginAttemptWindow)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET failed_attempts = $2, window_started_at = $3, locked_until = $4
		WHERE user_id = $1 AND purpose = 'login'
	`, userID, next, windowStarted, lock); err != nil {
		return 0, err
	}
	return maxMFALoginAttempts - int(next), nil
}

// CompleteMFALogin verifies the second-factor code for a pending token-flow
// login and, on success, issues the token pair.
func (s *Service) CompleteMFALogin(ctx context.Context, mfaToken, code, ip, ua string) (*TokenPair, error) {
	pair, _, err := s.CompleteMFALoginWith(ctx, mfaToken, MFAProof{Code: code}, ip, ua)
	return pair, err
}

// CompleteMFALoginWith is CompleteMFALogin met by any proof: a code, a
// passkey assertion, an approved push, or — for an enrolment challenge — the
// code confirming the authenticator app set up for it (whose new recovery
// codes it also returns) or a skip in the grace period.
func (s *Service) CompleteMFALoginWith(ctx context.Context, mfaToken string, proof MFAProof, ip, ua string) (*TokenPair, []string, error) {
	met, err := s.verifyAndConsumeMFAChallenge(ctx, mfaToken, proof)
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, met.userID, met.tenantID, ip, ua, met.method(), met.claims, nil, time.Time{})
	if err != nil {
		return nil, nil, err
	}
	// The second factor this sign-in met steps up the session it opens, and
	// only that one: no other session of the person's gains anything from it.
	if met.stepUpMethod != "" {
		if err := s.mfa.RecordVerification(ctx, tx, met.userID, pair.SessionID, met.stepUpMethod); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return pair, met.recoveryCodes, nil
}

// MFALoginSession is a hosted-login challenge met: the SSO session cookie
// value to write via SetLoginSessionCookie, and the recovery codes minted
// when the challenge was met by setting up an authenticator app.
type MFALoginSession struct {
	UserID uuid.UUID
	// TenantID is uuid.Nil when tenant-less.
	TenantID      uuid.UUID
	RawCookie     string
	RecoveryCodes []string
	// Deferred: an enrolment challenge skipped in the grace period. No
	// factor was met, so the device must not be remembered.
	Deferred bool
}

// CompleteMFALoginSession verifies the second-factor code for a pending
// hosted-login challenge and, on success, mints the SSO session cookie value
// (the cookie-flow analogue of CompleteMFALogin). Returns the user id, its
// tenant (uuid.Nil when tenant-less), and the raw cookie value to write via
// SetLoginSessionCookie.
func (s *Service) CompleteMFALoginSession(ctx context.Context, mfaToken, code, ip, ua string) (uuid.UUID, uuid.UUID, string, error) {
	res, err := s.CompleteMFALoginSessionWith(ctx, mfaToken, MFAProof{Code: code}, ip, ua)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	return res.UserID, res.TenantID, res.RawCookie, nil
}

// CompleteMFALoginSessionWith is CompleteMFALoginSession met by any proof
// (see CompleteMFALoginWith).
func (s *Service) CompleteMFALoginSessionWith(ctx context.Context, mfaToken string, proof MFAProof, ip, ua string) (*MFALoginSession, error) {
	// Any hook claims stashed on the challenge are discarded here — see the
	// note in BeginLoginSession on why this cookie flow doesn't carry them.
	met, err := s.verifyAndConsumeMFAChallenge(ctx, mfaToken, proof)
	if err != nil {
		return nil, err
	}
	factor := ""
	if !met.deferred && !met.riskVerified {
		factor = secondFactorMFA
	}
	raw, err := s.createLoginSession(ctx, met.userID, ip, ua, factor)
	if err != nil {
		return nil, err
	}
	// A confirmed risky sign-in met no factor either, so earns no remembered device.
	return &MFALoginSession{UserID: met.userID, TenantID: met.tenantID, RawCookie: raw,
		RecoveryCodes: met.recoveryCodes, Deferred: met.deferred || met.riskVerified}, nil
}

// CheckPassword runs the full credential check — sign-in lockout (see
// lockout.go), user lookup, password verify, transparent Argon2id
// rehash-on-login, and clear-on-success — returning the authenticated user
// plus any custom claims a wired Auth Hook asked to be injected into the
// eventual access token (nil when no hook is wired, or the hook returned
// none). Shared by API login (which then issues tokens) and the hosted-login
// SSO session (which sets a cookie). It deliberately does not mint tokens or
// sessions itself.
func (s *Service) CheckPassword(ctx context.Context, in SignInAttempt) (*user.User, map[string]any, error) {
	// Whether the organisation allows password sign-in. A hosted login names
	// the application, so its organisation decides before the password is
	// looked at — the same answer for any account or none. Without one, the
	// account's own organisation decides once the password is verified, so
	// only its owner sees that answer.
	signInTenant, err := s.SignInTenant(ctx, in.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if err := s.passwordAllowed(ctx, signInTenant); err != nil {
		return nil, nil, err
	}
	attempt, err := s.newSignInAttempt(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	if err := s.checkLockout(ctx, attempt); err != nil {
		return nil, nil, err
	}
	u, err := s.users.GetByEmailGlobal(ctx, in.Email)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			// No such account: spend a password verification and count the
			// failure exactly as for a wrong password, so neither the answer,
			// its timing nor the lockout tells the two apart.
			verifyPassword("", in.Password)
			if err := s.recordFailedSignIn(ctx, attempt); err != nil {
				return nil, nil, err
			}
			return nil, nil, errs.ErrAuthInvalidCredentials
		}
		return nil, nil, err
	}
	if u.Status != "active" && u.Status != "invited" {
		return nil, nil, errs.ErrAuthAccountInactive
	}
	hash, err := s.users.PasswordHash(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	if !verifyPassword(hash, in.Password) {
		if err := s.recordFailedSignIn(ctx, attempt); err != nil {
			return nil, nil, err
		}
		return nil, nil, errs.ErrAuthInvalidCredentials
	}
	if err := s.clearFailedSignIns(ctx, attempt); err != nil {
		return nil, nil, err
	}
	if signInTenant == uuid.Nil {
		if err := s.passwordAllowed(ctx, u.TenantID); err != nil {
			return nil, nil, err
		}
	}
	// Transparently upgrade legacy bcrypt / weak-param hashes to current
	// Argon2id on a successful login. Best-effort: never fail the login on it.
	if password.NeedsRehash(hash) {
		if nh, herr := password.Hash(in.Password); herr == nil {
			if uerr := s.q.UpdatePasswordCredentialHash(ctx, dbgen.UpdatePasswordCredentialHashParams{
				PasswordHash: nh,
				UserID:       u.ID,
			}); uerr != nil {
				slog.Warn("password rehash-on-login failed", "user_id", u.ID, "err", uerr)
			}
		}
	}
	// Actions/Hooks gate: a tenant policy endpoint may deny the sign-in, or
	// supply claims to carry into the token. No-op when no hook is wired, so
	// the common path is untouched.
	if s.loginHook != nil {
		claims, err := s.loginHook.Run(ctx, u.TenantID, u.ID, u.Email)
		if err != nil {
			return nil, nil, err
		}
		return u, claims, nil
	}
	return u, nil, nil
}

// IssuePair creates a session, mints an access+refresh pair, and records
// an audit row labelled with the login method ("password", "magic_link",
// "invite_accept", "oidc", "passkey", "social", …). The audit row lives
// inside the session-insert transaction so analytics never see a session
// without its provenance event.
func (s *Service) IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string) (*TokenPair, error) {
	return s.issuePair(ctx, userID, tenantID, ip, ua, method, nil)
}

// IssuePairWithClaims is IssuePair plus custom claims (typically sourced from
// an Auth Hook's decision, see LoginHook) to inject into the access token.
func (s *Service) IssuePairWithClaims(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string, claims map[string]any) (*TokenPair, error) {
	return s.issuePair(ctx, userID, tenantID, ip, ua, method, claims)
}

func (s *Service) issuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string, claims map[string]any) (*TokenPair, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, userID, tenantID, ip, ua, method, claims, nil, time.Time{})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// issuePairTx is issuePair inside the caller's transaction, which commits. The
// hook claims are stored with the session so renewals issue them again;
// auditMeta (may be nil) is added to the sign-in audit record. notAfter (zero:
// none) is when the sign-in this session continues ends: it ends no later.
func (s *Service) issuePairTx(ctx context.Context, tx pgx.Tx, userID, tenantID uuid.UUID, ip, ua, method string, claims, auditMeta map[string]any, notAfter time.Time) (*TokenPair, error) {
	// Every sign-in ends here, whatever its method, so a suspended or deleted
	// account is refused here, and the organisation's address rules
	// are asked here, before anything is written (the session limit below may
	// end another session).
	if err := s.refuseInactiveAccount(ctx, userID, tenantID, method, ip, ua); err != nil {
		return nil, err
	}
	if err := s.refuseInactiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	if err := s.checkAddress(ctx, tenantID, userID, ip, method); err != nil {
		return nil, err
	}
	sessionID := uuid.New()
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	// uuid.Nil = tenant-less: store NULL (the zero UUID would violate the FK).
	var tenantArg any
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		t := tenantID
		tenantArg = t
		tenantPtr = &t
	}
	var hookClaims []byte
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		hookClaims = raw
	}
	// The organisation's limit on one person's simultaneous sessions.
	if tenantID != uuid.Nil {
		if err := s.enforceSessionLimit(ctx, tx, userID, tenantID, ip, ua); err != nil {
			return nil, err
		}
	}
	// The organisation's own session bounds, else the platform's; taken now,
	// so a later change to the policy applies to new sessions only.
	maxAge, idle := s.sessionDefaults()
	var sessionExp, idleExp time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent, hook_claims, expires_at, idle_timeout, country,
		                           second_factor)
		SELECT $1, $2, $3, NULLIF($4,'')::inet, $5, $6,
		       LEAST(NOW() + COALESCE(sp.session_max_age, make_interval(secs => $7::float8)),
		             COALESCE($9::timestamptz, 'infinity'::timestamptz)),
		       COALESCE(sp.session_idle_timeout, make_interval(secs => $8::float8)),
		       NULLIF($10, ''), NULLIF($11, '')
		FROM (VALUES (1)) AS one
		LEFT JOIN tenant.security_policies sp ON sp.tenant_id = $3
		RETURNING expires_at, LEAST(last_seen_at + idle_timeout, expires_at)
	`, sessionID, userID, tenantArg, ipArg, ua, hookClaims, maxAge.Seconds(), idle.Seconds(), notAfterArg(notAfter),
		httpx.GeoCountry(ctx), secondFactorOfMethod(method)).Scan(&sessionExp, &idleExp); err != nil {
		return nil, err
	}
	access, exp, err := s.tokens.IssueSessionAccess(userID, tenantID, sessionID, claims, sessionExp)
	if err != nil {
		return nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	if _, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: refreshHash,
		ExpiresAt: s.refreshExpiry(sessionExp),
	}); err != nil {
		return nil, err
	}
	if method == "" {
		method = "unknown"
	}
	meta := map[string]any{"method": method}
	for k, v := range auditMeta {
		meta[k] = v
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       "auth.login_succeeded",
		ResourceType: "session",
		ResourceID:   &sessionID,
		IP:           ip,
		UserAgent:    ua,
		Metadata:     meta,
	}); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     refreshRaw,
		SessionExpiresAt: sessionExp,
		IdleExpiresAt:    idleExp,
		SessionID:        sessionID,
		UserID:           userID,
		TenantID:         tenantPtr,
	}, nil
}

// notAfterArg is a session's latest end for the insert: NULL for none.
func notAfterArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// refreshExpiry is when a refresh token issued now expires: its usual
// lifetime, but never after the session it renews has ended.
func (s *Service) refreshExpiry(sessionExp time.Time) time.Time {
	exp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	if sessionExp.Before(exp) {
		return sessionExp
	}
	return exp
}

// Refresh rotates the provided refresh token: the old row is marked used,
// a new one is inserted, and a fresh access token is signed. Reuse of an
// already-used token revokes the whole session (token theft mitigation)
// and emits an audit event + outbox event so notifications (email,
// webhook) can reach the user.
func (s *Service) Refresh(ctx context.Context, in RefreshInput) (*TokenPair, error) {
	hash := tokens.HashRefresh(in.RefreshToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		id          uuid.UUID
		sessionID   uuid.UUID
		usedAt      *time.Time
		expiresAt   time.Time
		sessionRev  *time.Time
		userID      uuid.UUID
		tenantPtr   *uuid.UUID // NULL for a tenant-less session
		userStatus  string
		userDeleted *time.Time
		hookClaims  []byte
		sessionExp  time.Time
		pastMaxAge  bool
		pastIdle    bool
		// tenantActive: the session's organisation is neither suspended nor
		// deleted (true for a tenant-less session).
		tenantActive bool
	)
	// Whether the session had reached its maximum age or idle timeout by the
	// time it ended — now, if it has not ended — is decided on the database's
	// clock, as the bounds were set.
	row := tx.QueryRow(ctx, `
		SELECT rt.id, rt.session_id, rt.used_at, rt.expires_at,
		       s.revoked_at, s.user_id, s.tenant_id, u.status, u.deleted_at, s.hook_claims,
		       s.expires_at,
		       s.expires_at <= COALESCE(s.revoked_at, NOW()),
		       s.last_seen_at + s.idle_timeout <= COALESCE(s.revoked_at, NOW()),
		       s.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL)
		FROM auth.refresh_tokens rt
		JOIN auth.sessions s ON s.id = rt.session_id
		JOIN "user".users u ON u.id = s.user_id
		LEFT JOIN tenant.tenants t ON t.id = s.tenant_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt, s
	`, hash)
	if err := row.Scan(&id, &sessionID, &usedAt, &expiresAt, &sessionRev, &userID, &tenantPtr, &userStatus, &userDeleted, &hookClaims,
		&sessionExp, &pastMaxAge, &pastIdle, &tenantActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrAuthRefreshTokenInvalid
		}
		return nil, err
	}
	// uuid.Nil = tenant-less session; preserved across refresh.
	var tenantID uuid.UUID
	if tenantPtr != nil {
		tenantID = *tenantPtr
	}
	// A session past its maximum age or idle timeout has ended, whatever the
	// client was told and whether or not it is the first renewal to notice.
	// The first one records the ending; it is never renewed.
	if pastMaxAge || pastIdle {
		if sessionRev == nil {
			reason := timedOutIdle
			if pastMaxAge {
				reason = timedOutMaxAge
			}
			if err := s.endTimedOutSession(ctx, tx, userID, tenantID, sessionID, reason, in); err != nil {
				return nil, err
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
		}
		return nil, errs.ErrAuthSessionTimedOut
	}
	if sessionRev != nil {
		return nil, errs.ErrAuthSessionRevoked
	}
	// A session can outlive the account it belongs to: a plain status
	// change (PATCH /users/{id}) or a soft-delete doesn't touch
	// auth.sessions at all, so without this check a suspended/deleted
	// user's still-valid refresh token would keep minting fresh access
	// tokens indefinitely.
	if userDeleted != nil || userStatus == "suspended" {
		return nil, errs.ErrAuthAccountSuspended
	}
	// The same for the organisation: suspending or deleting it ends its
	// sessions, and a refresh token that outlived that is refused.
	if !tenantActive {
		return nil, errs.ErrAuthTenantInactive
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrAuthRefreshTokenInvalid
	}
	if usedAt != nil {
		// Reuse — assume theft. Revoke the session, write an audit row,
		// and enqueue an outbox event so downstream notifiers (email,
		// webhook) can alert the user. All three happen atomically with
		// the revocation so a partial failure leaves no inconsistent
		// state.
		if err := s.handleRefreshReuse(ctx, tx, userID, tenantID, sessionID, id, in); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrAuthSessionRevoked
	}

	// A session renews only from an address its organisation still allows, so
	// a newly blocked address stops renewing. The session itself stays: it
	// renews again from an allowed address.
	if err := s.checkAddress(ctx, tenantID, userID, in.IP, "refresh"); err != nil {
		return nil, err
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	newID, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: newHash,
		ExpiresAt: s.refreshExpiry(sessionExp),
	})
	if err != nil {
		return nil, err
	}
	if err := s.q.WithTx(tx).MarkRefreshTokenUsed(ctx, dbgen.MarkRefreshTokenUsedParams{
		ReplacedBy: pgtype.UUID{Bytes: newID, Valid: true},
		ID:         id,
	}); err != nil {
		return nil, err
	}
	// The renewal is the session's use: its idle timeout counts from now.
	idleExp, err := s.q.WithTx(tx).UpdateSessionLastSeen(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	// The hook ran when the session was opened; its claims stay with the session.
	var claims map[string]any
	if len(hookClaims) > 0 {
		if err := json.Unmarshal(hookClaims, &claims); err != nil {
			return nil, err
		}
	}
	access, exp, err := s.tokens.IssueSessionAccess(userID, tenantID, sessionID, claims, sessionExp)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     newRaw,
		SessionExpiresAt: sessionExp,
		IdleExpiresAt:    idleExp,
		SessionID:        sessionID,
		UserID:           userID,
		TenantID:         tenantPtr,
	}, nil
}

// buildReuseEvents constructs the audit + outbox events emitted when a
// refresh-token reuse is detected. Exported as a free function so tests
// can verify the payload shape without a DB round-trip.
func buildReuseEvents(userID, tenantID, sessionID, refreshID uuid.UUID, in RefreshInput) (audit.Event, outbox.Event) {
	meta := map[string]any{
		"session_id":       sessionID,
		"refresh_token_id": refreshID,
		"reason":           "refresh_token_reuse",
	}
	if in.IP != "" {
		meta["ip"] = in.IP
	}
	if in.UserAgent != "" {
		meta["user_agent"] = in.UserAgent
	}

	tid := tenantID
	uid := userID
	sid := sessionID
	ae := audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "auth.token_reuse_detected",
		ResourceType: "session",
		ResourceID:   &sid,
		IP:           in.IP,
		UserAgent:    in.UserAgent,
		RequestID:    in.RequestID,
		Metadata:     meta,
	}
	oe := outbox.Event{
		AggregateID: sessionID,
		Topic:       "auth",
		EventType:   "auth.session.revoked_for_reuse",
		Payload: map[string]any{
			"user_id":    userID,
			"tenant_id":  tenantID,
			"session_id": sessionID,
			"ip":         in.IP,
			"user_agent": in.UserAgent,
		},
	}
	return ae, oe
}

// handleRefreshReuse atomically records and revokes a stolen-token
// situation. Caller has already loaded the offending refresh row and is
// inside a transaction that will be committed only if every step here
// succeeds — leaving no half-state if e.g. the outbox insert fails.
func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx,
	userID, tenantID, sessionID, refreshID uuid.UUID, in RefreshInput,
) error {
	if err := s.q.WithTx(tx).RevokeSessionById(ctx, sessionID); err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonReuseDetected,
		sessionsignal.Session{ID: sessionID, UserID: userID, TenantID: tenantID})

	auditEvent, outboxEvent := buildReuseEvents(userID, tenantID, sessionID, refreshID, in)
	if err := audit.Record(ctx, tx, auditEvent); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outboxEvent); err != nil {
		return err
	}

	slog.Warn("refresh token reuse — session revoked",
		"user_id", userID,
		"tenant_id", tenantID,
		"session_id", sessionID,
		"ip", in.IP,
	)
	return nil
}

// Logout revokes a session (covers both self-service logout and an
// admin/API-driven revoke of another session — same call, same effect).
// Idempotent: revoking an already-revoked or nonexistent session is a no-op,
// not an error.
// Logout revokes a session, scoped to its owner: a caller can only revoke a
// session that belongs to them (userID), so passing another user's session id
// is a no-op rather than a cross-user takedown.
func (s *Service) Logout(ctx context.Context, sessionID, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tenantID, err := s.q.WithTx(tx).RevokeSessionForUser(ctx, dbgen.RevokeSessionForUserParams{
		SessionID: sessionID,
		UserID:    userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonLogout,
		endedSessions(userID, []uuid.UUID{sessionID}, []pgtype.UUID{tenantID})...)
	return tx.Commit(ctx)
}

// RevokeOtherSessionsInput names the caller and the session they keep.
// CurrentSessionID must come from the caller's own access token, never from
// anything the client supplies.
type RevokeOtherSessionsInput struct {
	UserID           uuid.UUID
	CurrentSessionID uuid.UUID
	TenantID         *uuid.UUID
	IP               string
	UserAgent        string
	RequestID        string
}

// RevokeOtherSessions ends every live session the user holds except the current
// one and returns how many it ended. Ending a session is what invalidates its
// refresh tokens: Refresh rejects any token whose session is revoked.
//
// It is all-or-nothing: the revocation and its audit record commit together, so
// a failure ends nothing and is never reported as success. The user row is
// locked first, so two of the user's sessions asking at once run one after the
// other; the second then finds its own session ended and gets
// ErrAuthSessionRevoked. That check also stops a still-unexpired access token
// from an ended session from ending the sessions that remain.
func (s *Service) RevokeOtherSessions(ctx context.Context, in RevokeOtherSessionsInput) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if _, err := q.LockUserForSessionRevocation(ctx, in.UserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, errs.ErrUnauthorized
		}
		return 0, err
	}
	live, err := q.IsSessionLiveForUser(ctx, dbgen.IsSessionLiveForUserParams{
		SessionID: in.CurrentSessionID,
		UserID:    in.UserID,
	})
	if err != nil {
		return 0, err
	}
	if !live {
		return 0, errs.ErrAuthSessionRevoked
	}
	rows, err := q.RevokeOtherSessionsForUser(ctx, dbgen.RevokeOtherSessionsForUserParams{
		UserID:        in.UserID,
		KeepSessionID: in.CurrentSessionID,
	})
	if err != nil {
		return 0, err
	}
	revoked := int64(len(rows))
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonOtherSessionsRevoked, otherSessionsEnded(in.UserID, rows)...)
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: in.TenantID, ActorUserID: &in.UserID, ActorType: "user",
		Action: "auth.other_sessions_revoked", ResourceType: "user", ResourceID: &in.UserID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: map[string]any{"revoked_sessions": revoked, "kept_session_id": in.CurrentSessionID},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return revoked, nil
}

// SignInsEnded counts what signing someone out everywhere ended (see
// user.SignInsEnded).
type SignInsEnded = user.SignInsEnded

// RevokeAllSessionsInput names the caller. SessionID must come from the
// caller's own access token, never from anything the client supplies.
type RevokeAllSessionsInput struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	TenantID  *uuid.UUID
	IP        string
	UserAgent string
	RequestID string
}

// RevokeAllSessions signs the caller out everywhere: every API and console
// session including the current one, every hosted-login session and every
// application grant (see EndAllSignIns), and records it as a self-initiated
// global sign-out. Access tokens already issued stay valid until they expire.
//
// The presented token must stand for one of the caller's own sessions — live or
// already ended — so an application's access token (which names no session) or
// a token naming someone else's session is refused. An ended session is allowed
// so that repeating the call, e.g. after a lost response, succeeds and changes
// nothing (all counts zero). It is all-or-nothing: the ending and its audit
// record commit together.
func (s *Service) RevokeAllSessions(ctx context.Context, in RevokeAllSessionsInput) (SignInsEnded, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SignInsEnded{}, err
	}
	defer tx.Rollback(ctx)
	owned, err := s.q.WithTx(tx).IsSessionOfUser(ctx, dbgen.IsSessionOfUserParams{
		SessionID: in.SessionID,
		UserID:    in.UserID,
	})
	if err != nil {
		return SignInsEnded{}, err
	}
	if !owned {
		return SignInsEnded{}, errs.ErrUnauthorized
	}
	var ended SignInsEnded
	ended, err = s.EndAllSignIns(ctx, tx, in.UserID, sessionsignal.ReasonAllSessionsRevoked)
	if err != nil {
		return SignInsEnded{}, err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: in.TenantID, ActorUserID: &in.UserID, ActorType: "user",
		Action: "auth.all_sessions_revoked", ResourceType: "user", ResourceID: &in.UserID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: map[string]any{
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
			"session_id":                   in.SessionID,
		},
	}); err != nil {
		return SignInsEnded{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SignInsEnded{}, err
	}
	return ended, nil
}

// maxGrantPasses bounds the passes EndAllSignIns makes over a user's
// application grants (see there).
const maxGrantPasses = 5

// EndAllSignIns ends, inside tx, every way the user is signed in, in all three
// places, and returns how many it ended in each:
//   - sessions: every live API and console session (their refresh tokens stop
//     working with them);
//   - loginSessions: every hosted-login browser session, deleted as hosted
//     sign-out deletes one, counting those not yet expired;
//   - appGrants: every application's refresh grant, for every application.
//
// It locks the user row first (the order bulk session revocation uses), so it
// runs one at a time with other bulk revocations and password changes for the
// same user. Nothing is committed here: the caller records its audit event in
// the same tx and commits. Used by self-service sign-out everywhere and by the
// administrator's force sign-out. errs.ErrNotFound for an unknown user.
//
// reason is why, for the session.revoked signals of the sessions it ends
// (self-service sign out everywhere, or an administrator's force sign-out).
func (s *Service) EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) (SignInsEnded, error) {
	var ended SignInsEnded
	q := s.q.WithTx(tx)
	if _, err := q.LockUserForSessionRevocation(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SignInsEnded{}, errs.ErrNotFound
		}
		return SignInsEnded{}, err
	}
	rows, err := q.RevokeAllSessionsForUser(ctx, userID)
	if err != nil {
		return SignInsEnded{}, err
	}
	ended.Sessions = int64(len(rows))
	signals := make([]sessionsignal.Session, len(rows))
	for i, r := range rows {
		signals[i] = sessionsignal.Session{ID: r.ID, UserID: userID}
		if r.TenantID.Valid {
			signals[i].TenantID = uuid.UUID(r.TenantID.Bytes)
		}
	}
	s.signals.Revoked(ctx, tx, reason, signals...)
	if ended.LoginSessions, err = q.EndLoginSessionsForUser(ctx, userID); err != nil {
		return SignInsEnded{}, err
	}
	// The ways back in that are not sessions: a remembered device would skip
	// the second factor at the next password sign-in, and an unredeemed code
	// or an approved device or back-channel request would still turn into a
	// grant. Codes are spent before the grant passes below, so a grant a
	// redemption under way writes is ended by them.
	if ended.TrustedDevices, err = q.DeleteTrustedDevicesForUser(ctx, userID); err != nil {
		return SignInsEnded{}, err
	}
	denyDevices := func(ctx context.Context, id uuid.UUID) (int64, error) {
		return q.DenyDeviceAuthorizationsForUser(ctx, pgtype.UUID{Bytes: id, Valid: true})
	}
	for _, deny := range []func(context.Context, uuid.UUID) (int64, error){
		q.SpendAuthorizationCodesForUser, denyDevices, q.DenyBackchannelRequestsForUser,
	} {
		n, err := deny(ctx, userID)
		if err != nil {
			return SignInsEnded{}, err
		}
		ended.PendingAuthorizations += n
	}
	// An application renewing a grant at this moment locks the token it
	// presented, writes the successor and commits — possibly after a pass has
	// already taken its snapshot, so that pass cannot see the successor. A
	// further pass (a new statement, a new snapshot) does; repeat until a pass
	// finds nothing left. Bounded: a renewal has to win a race against a pass
	// that is already waiting for it, so one extra pass is the norm.
	for pass := 0; pass < maxGrantPasses; pass++ {
		row, err := q.RevokeAppGrantsForUser(ctx, userID)
		if err != nil {
			return SignInsEnded{}, err
		}
		ended.AppGrants += row.Live
		if row.Touched == 0 {
			break
		}
	}
	return ended, nil
}

type ChangePasswordInput struct {
	UserID        uuid.UUID
	KeepSessionID uuid.UUID
	TenantID      *uuid.UUID
	Current       string
	Next          string
	IP            string
	UserAgent     string
	RequestID     string
}

// ChangePassword atomically updates the credential, revokes every other
// session, and records durable audit/outbox evidence. The authenticated current
// session remains active so the user is not signed out of the initiating flow.
//
// The new password is checked against the rules of the organisation the
// account belongs to — not the session's tenant, which the user chooses — or
// the platform baseline for a tenant-less account. The check runs before the
// current password is verified and depends only on the new one, so a refusal
// says nothing about the stored credential.
func (s *Service) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	account, err := s.users.Get(ctx, in.UserID)
	if err != nil {
		return err
	}
	if err := s.checkNewPassword(ctx, account.TenantID, account.Email, in.Next); err != nil {
		return err
	}
	nh, err := password.Hash(in.Next)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var lockedUser uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM "user".users WHERE id = $1 FOR UPDATE`, in.UserID).Scan(&lockedUser); err != nil {
		return err
	}
	var currentHash string
	err = tx.QueryRow(ctx, `SELECT password_hash FROM auth.password_credentials WHERE user_id = $1`, in.UserID).Scan(&currentHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if currentHash != "" && !password.Verify(currentHash, in.Current) {
		return errs.ErrAuthInvalidCredentials
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
	`, in.UserID, nh); err != nil {
		return err
	}
	rows, err := s.q.WithTx(tx).RevokeOtherSessionsForUser(ctx, dbgen.RevokeOtherSessionsForUserParams{
		UserID:        in.UserID,
		KeepSessionID: in.KeepSessionID,
	})
	if err != nil {
		return err
	}
	revoked := int64(len(rows))
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonPasswordChanged, otherSessionsEnded(in.UserID, rows)...)
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: in.TenantID, ActorUserID: &in.UserID, ActorType: "user",
		Action: "auth.password_changed", ResourceType: "user", ResourceID: &in.UserID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: map[string]any{"revoked_sessions": revoked, "kept_session_id": in.KeepSessionID},
	}); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: in.UserID, Topic: "auth", EventType: "auth.password.changed",
		Payload: map[string]any{
			"user_id": in.UserID, "tenant_id": in.TenantID,
			"kept_session_id": in.KeepSessionID, "revoked_sessions": revoked,
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// HasPassword reports whether the user has a password credential set — lets the
// account UI show "set a password" vs "change password".
func (s *Service) HasPassword(ctx context.Context, userID uuid.UUID) (bool, error) {
	hash, err := s.users.PasswordHash(ctx, userID)
	if err != nil {
		return false, err
	}
	return hash != "", nil
}

// ReauthPassword re-verifies a password for a sensitive action (e.g. account
// deletion). hasPassword=false means the account is password-less (social /
// passkey) — the caller decides whether to require some other proof; ok reports
// whether the supplied password matched when one is set.
func (s *Service) ReauthPassword(ctx context.Context, userID uuid.UUID, plain string) (hasPassword, ok bool, err error) {
	hash, herr := s.users.PasswordHash(ctx, userID)
	if herr != nil {
		return false, false, herr
	}
	if hash == "" {
		return false, false, nil
	}
	return true, plain != "" && password.Verify(hash, plain), nil
}

// SignInMethods counts the user's ways to sign in (see user.SignInMethods).
func (s *Service) SignInMethods(ctx context.Context, userID uuid.UUID) (user.SignInMethods, error) {
	return user.CountSignInMethods(ctx, s.pool, userID)
}

type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	IP         *string    `json:"ip"`
	UserAgent  *string    `json:"user_agent"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	// ExpiresAt is when the session ends however active it is, and
	// IdleExpiresAt when it ends unless renewed first. Status is "active",
	// "revoked" (ended by sign-out or revocation) or "expired" (reached its
	// maximum age or idle timeout first).
	ExpiresAt     time.Time `json:"expires_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	Status        string    `json:"status"`
	// Device describes the device and browser in words ("Chrome on macOS",
	// "Unknown device"), read from the user agent on the server so every
	// surface names it alike; DeviceKind is desktop, mobile, tablet or
	// unknown. The raw user agent stays in UserAgent, for support.
	Device     string `json:"device"`
	DeviceKind string `json:"device_kind"`
	// Country is where the session was opened, approximately (ISO 3166-1
	// alpha-2), when the deployment supplies it; omitted otherwise.
	Country string `json:"country,omitempty"`
	// Current marks the session the request listing them was made with.
	Current bool `json:"current"`
}

func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	page, err := s.ListSessionsPage(ctx, userID, 100, "")
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

type SessionPage struct {
	Items      []Session `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
	HasMore    bool      `json:"has_more"`
	Total      int       `json:"total"`
}

// ListSessionsPage lists the user's sessions, newest first.
func (s *Service) ListSessionsPage(ctx context.Context, userID uuid.UUID, limit int, cursor string) (*SessionPage, error) {
	return s.ListSessionsPageFor(ctx, userID, uuid.Nil, limit, cursor)
}

// ListSessionsPageFor is ListSessionsPage marking current (uuid.Nil: none) as
// the caller's own session.
func (s *Service) ListSessionsPageFor(ctx context.Context, userID, current uuid.UUID, limit int, cursor string) (*SessionPage, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	var cursorID uuid.UUID
	var cursorAt time.Time
	if cursor != "" {
		parsed, err := uuid.Parse(cursor)
		if err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid session cursor")
		}
		cursorID = parsed
		if err := s.pool.QueryRow(ctx, `
			SELECT sess.created_at
			FROM auth.sessions sess
			JOIN "user".users u ON u.id = sess.user_id
			WHERE sess.id = $1 AND sess.user_id = $2 AND u.deleted_at IS NULL
		`, cursorID, userID).Scan(&cursorAt); errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrBadRequest.WithDetail("invalid session cursor")
		} else if err != nil {
			return nil, err
		}
	}
	// Soft-deleted users keep their session rows for audit purposes but
	// must not surface them via admin or self-service listings. Filter
	// at the join rather than relying on the caller to know about
	// `users.deleted_at`.
	rows, err := s.pool.Query(ctx, `
		SELECT sess.id, sess.user_id, sess.tenant_id, host(sess.ip), sess.user_agent,
		       sess.created_at, sess.last_seen_at, sess.revoked_at,
		       sess.expires_at, ends.idle,
		       CASE WHEN ends.idle <= COALESCE(sess.revoked_at, NOW()) THEN 'expired'
		            WHEN sess.revoked_at IS NOT NULL THEN 'revoked'
		            ELSE 'active' END,
		       COALESCE(sess.country, '')
		FROM auth.sessions sess
		CROSS JOIN LATERAL (SELECT LEAST(sess.last_seen_at + sess.idle_timeout, sess.expires_at) AS idle) ends
		JOIN "user".users u ON u.id = sess.user_id
		WHERE sess.user_id = $1 AND u.deleted_at IS NULL AND sess.superseded_by IS NULL
		  AND ($2::boolean = FALSE OR (sess.created_at, sess.id) < ($3, $4))
		ORDER BY sess.created_at DESC, sess.id DESC
		LIMIT $5
	`, userID, cursor != "", cursorAt, cursorID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Session, 0, limit+1)
	for rows.Next() {
		var session Session
		var tenantID pgtype.UUID
		if err := rows.Scan(&session.ID, &session.UserID, &tenantID, &session.IP, &session.UserAgent, &session.CreatedAt, &session.LastSeenAt, &session.RevokedAt,
			&session.ExpiresAt, &session.IdleExpiresAt, &session.Status, &session.Country); err != nil {
			return nil, err
		}
		ua := ""
		if session.UserAgent != nil {
			ua = *session.UserAgent
		}
		device := useragent.Parse(ua)
		session.Device, session.DeviceKind = device.Label(), device.Kind
		session.Current = current != uuid.Nil && session.ID == current
		if tenantID.Valid {
			session.TenantID = uuid.UUID(tenantID.Bytes)
		}
		out = append(out, session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	nextCursor := ""
	if hasMore && len(out) > 0 {
		nextCursor = out[len(out)-1].ID.String()
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM auth.sessions sess
		JOIN "user".users u ON u.id = sess.user_id
		WHERE sess.user_id = $1 AND u.deleted_at IS NULL AND sess.superseded_by IS NULL
	`, userID).Scan(&total); err != nil {
		return nil, err
	}
	return &SessionPage{Items: out, NextCursor: nextCursor, HasMore: hasMore, Total: total}, nil
}
