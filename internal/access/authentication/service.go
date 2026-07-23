// Package auth handles login, refresh, logout, and session storage.
// Access & ID tokens are signed with ES256 (asymmetric) and verifiable via the
// public JWKS; see internal/platform/tokens.
package auth

import (
	"context"
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
	"github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	users  *user.Repository
	tokens *tokens.Issuer
	// breach is the optional breached-password checker (nil = feature off,
	// a no-op). Set via SetBreachChecker; consulted on Signup.
	breach *hibp.Checker
	// mfa gates login on a second factor (nil = MFA-at-login off). Set via
	// SetMFA; kept as an interface so package auth doesn't import package mfa.
	mfa MFAEnroller
	// regPolicy gates hosted self-registration and validates new passwords
	// against the tenant policy (nil = self-registration off). Set via
	// SetRegistrationPolicy; an interface so auth doesn't import authpolicy.
	regPolicy RegistrationPolicy
	// anomaly receives security signals (nil = recording off). Set via
	// SetAnomalyRecorder; an interface so auth doesn't import the threat package.
	anomaly AnomalyRecorder
	// devicePolicy reports whether a tenant has opted into adaptive MFA
	// (trusted-device skip). nil = always-on MFA. Set via SetDevicePolicy.
	devicePolicy DevicePolicy
	// riskAssessor overrides trusted-device skip when risk is too high. nil = no override.
	riskAssessor RiskAssessor
	// loginHook is an optional synchronous policy gate run after credentials
	// verify (nil = no gate). Set via SetLoginHook.
	loginHook LoginHook
	// emitter delivers session.revoked signals to a tenant's webhook
	// subscriptions (nil = emission off). Set via SetEmitter.
	emitter EventEmitter
}

func NewService(pool *pgxpool.Pool, users *user.Repository, t *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), users: users, tokens: t}
}

// EventEmitter delivers a webhook-shaped event to a tenant's subscriptions.
// Satisfied by *webhook.Service.Enqueue; kept as a func type (matching the
// same pattern used by domains/developer/agents) so auth doesn't import the
// webhooks package. Wired via SetEmitter.
type EventEmitter func(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error

// SetEmitter wires webhook delivery for session-revocation signals. Called
// from cmd/server/main.go.
func (s *Service) SetEmitter(e EventEmitter) { s.emitter = e }

// emit is a best-effort webhook delivery: a failure here must never fail the
// revocation it's describing (the session is already dead either way), so
// errors are logged, not returned. tenantID == uuid.Nil (a tenant-less
// session) is skipped — there's no tenant to hold a webhook subscription.
func (s *Service) emit(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) {
	if s.emitter == nil || tenantID == uuid.Nil {
		return
	}
	if err := s.emitter(ctx, tenantID, eventType, payload); err != nil {
		slog.Warn("auth: emit webhook event", "event_type", eventType, "err", err)
	}
}

// MFAEnroller is the slice of the MFA service the auth package needs to enforce
// a second factor at login. Wired in cmd/server/main.go via SetMFA.
type MFAEnroller interface {
	// IsEnrolled reports whether the user has a usable login second factor.
	IsEnrolled(ctx context.Context, userID uuid.UUID) (bool, error)
	// VerifyForLogin verifies a TOTP/recovery code for the pending login;
	// (false, nil) means the code was wrong, a non-nil error is infrastructure.
	VerifyForLogin(ctx context.Context, userID uuid.UUID, code string) (bool, error)
}

// SetMFA wires the MFA-at-login checker. Called from cmd/server/main.go.
func (s *Service) SetMFA(m MFAEnroller) { s.mfa = m }

// RegistrationPolicy is the slice of the auth-policy service the auth package
// needs to run hosted self-registration: the per-tenant on/off gate and the
// per-tenant password validation (length/complexity + breach). Satisfied by
// *authpolicy.Service. Wired in cmd/server/main.go via SetRegistrationPolicy.
type RegistrationPolicy interface {
	SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
	ValidateForTenant(ctx context.Context, tenantID uuid.UUID, pw string) error
}

// SetRegistrationPolicy wires the hosted self-registration gate + password
// policy. Called from cmd/server/main.go.
func (s *Service) SetRegistrationPolicy(p RegistrationPolicy) { s.regPolicy = p }

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
// off). Currently notified when an account crosses the brute-force lockout
// threshold. Kept as an interface so auth doesn't import the threat package;
// satisfied by *threat.Service. Wired via SetAnomalyRecorder.
type AnomalyRecorder interface {
	OnAccountLocked(ctx context.Context, email string)
}

// SetAnomalyRecorder wires the security-anomaly recorder. Called from
// cmd/server/main.go.
func (s *Service) SetAnomalyRecorder(a AnomalyRecorder) { s.anomaly = a }

// DevicePolicy reports whether a tenant has opted into adaptive MFA (skipping
// the second factor on a trusted device). Satisfied by *authpolicy.Service;
// kept as an interface so auth doesn't import authpolicy. Wired via
// SetDevicePolicy.
type DevicePolicy interface {
	RememberDeviceEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// SetDevicePolicy wires the adaptive-MFA (trusted-device) gate. Called from
// cmd/server/main.go.
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

// SetRiskAssessor wires the adaptive-MFA risk override. Called from cmd/server/main.go.
func (s *Service) SetRiskAssessor(r RiskAssessor) { s.riskAssessor = r }

// LoginHook is a synchronous policy gate run after credentials verify: it
// returns a non-nil error to DENY the sign-in, or nil to allow — in which case
// the returned map (possibly nil) carries custom claims to inject into the
// issued access token. nil hook = no gate. Satisfied by *authhook.Service; an
// interface so auth doesn't import it.
type LoginHook interface {
	Run(ctx context.Context, tenantID, userID uuid.UUID, email string) (map[string]any, error)
}

// SetLoginHook wires the post-credential Actions/Hooks gate. Called from
// cmd/server/main.go.
func (s *Service) SetLoginHook(h LoginHook) { s.loginHook = h }

// mfaChallengeTTL bounds how long a pending second-factor login stays valid.
const mfaChallengeTTL = 10 * time.Minute

// LoginResult is either a full token pair (no MFA needed) or a pending MFA
// challenge that must be completed via CompleteMFALogin before tokens issue.
type LoginResult struct {
	Pair        *TokenPair
	MFARequired bool
	MFAToken    string
	Methods     []string
}

// LoginSessionResult is the hosted-login (cookie) analogue of LoginResult:
// either a ready SSO session (RawCookie set, to be written via
// SetLoginSessionCookie) or a pending MFA challenge to complete via
// CompleteMFALoginSession before the cookie is issued.
type LoginSessionResult struct {
	UserID      uuid.UUID
	RawCookie   string
	MFARequired bool
	MFAToken    string
	Methods     []string
}

// SetBreachChecker wires the breached-password checker. Called from
// cmd/server/main.go only when BREACHED_PASSWORD_CHECK is enabled.
func (s *Service) SetBreachChecker(c *hibp.Checker) { s.breach = c }

type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
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
	SessionID    uuid.UUID `json:"session_id"`
	UserID       uuid.UUID `json:"user_id"`
	// Tenant the token is scoped to; nil/omitted for a tenant-less session.
	TenantID *uuid.UUID `json:"tenant_id,omitempty"`
}

// Signup creates a tenant-less identity (user + password + session) and logs them in; no tenant or role is created.
func (s *Service) Signup(ctx context.Context, in SignupInput) (*TokenPair, *user.User, *TenantBrief, error) {
	// Password strength gate. The offline baseline (common-password denylist,
	// equals-email, uniform/sequential) always runs — no network, works in dev.
	if reason := password.WeakReason(in.Password, in.Email); reason != "" {
		return nil, nil, nil, errs.ErrUnprocessable.WithMessage(reason)
	}
	// Breached-password gate. Tenant-less, so there's no per-tenant policy to
	// consult here — just the global HIBP signal. No-op when disabled (nil
	// checker) and fail-open inside PwnedAllowOnError.
	if s.breach.PwnedAllowOnError(ctx, in.Password) {
		return nil, nil, nil, errs.ErrUnprocessable.WithMessage("This password has appeared in known data breaches. Choose a different one.")
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
			return nil, nil, nil, errs.ErrConflict.WithDetail("email already exists")
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
	if err := s.q.WithTx(tx).InsertTenantlessSession(ctx, dbgen.InsertTenantlessSessionParams{
		ID:        sessionID,
		UserID:    u.ID,
		Ip:        in.IP,
		UserAgent: &in.UserAgent,
	}); err != nil {
		return nil, nil, nil, err
	}
	access, exp, err := s.tokens.IssueAccess(u.ID, uuid.Nil, sessionID, "")
	if err != nil {
		return nil, nil, nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, nil, nil, err
	}
	refreshExp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	if _, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: refreshHash,
		ExpiresAt: refreshExp,
	}); err != nil {
		return nil, nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		RefreshToken: refreshRaw,
		SessionID:    sessionID,
		UserID:       u.ID,
	}, u, nil, nil
}

// SwitchTenant mints a token pair scoped to tenantID if the user is a member; ErrForbidden otherwise.
func (s *Service) SwitchTenant(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*TokenPair, error) {
	member, err := s.q.CheckTenantMembership(ctx, dbgen.CheckTenantMembershipParams{
		UserID:   userID,
		TenantID: tenantID,
	})
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, errs.ErrForbidden.WithDetail("not a member of this tenant")
	}
	return s.IssuePair(ctx, userID, tenantID, ip, ua, "tenant_switch")
}

// Login verifies the password and, when the user has a second factor enrolled,
// returns an MFA challenge instead of tokens (complete it via CompleteMFALogin).
// Otherwise it returns a full token pair.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	u, claims, err := s.CheckPassword(ctx, in.Email, in.Password)
	if err != nil {
		return nil, err
	}
	if s.mfa != nil {
		enrolled, err := s.mfa.IsEnrolled(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if enrolled {
			token, err := s.createMFAChallenge(ctx, u.ID, u.TenantID, claims)
			if err != nil {
				return nil, err
			}
			return &LoginResult{MFARequired: true, MFAToken: token, Methods: []string{"totp", "recovery_code"}}, nil
		}
	}
	pair, err := s.IssuePairWithClaims(ctx, u.ID, u.TenantID, in.IP, in.UserAgent, "password", claims)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Pair: pair}, nil
}

// BeginLoginSession is the hosted-login (cookie) equivalent of Login: it
// verifies the password and, when the user has a second factor enrolled,
// returns an MFA challenge instead of an SSO session (complete it via
// CompleteMFALoginSession). Otherwise it mints the SSO session cookie value.
// Without this check the cookie flow would bypass MFA that the token flow
// enforces.
func (s *Service) BeginLoginSession(ctx context.Context, email, password, ip, ua, trustedToken, country string) (*LoginSessionResult, error) {
	// Hook-issued claims aren't threaded into the hosted-login cookie flow: the
	// SSO cookie is opaque, and any JWT is minted later by the OIDC authorize
	// flow for a specific client, decoupled from this call — a separate,
	// larger integration than the direct API-token login this powers.
	u, _, err := s.CheckPassword(ctx, email, password)
	if err != nil {
		return nil, err
	}
	if s.mfa != nil {
		enrolled, err := s.mfa.IsEnrolled(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if enrolled && !s.deviceTrusted(ctx, u.ID, u.TenantID, trustedToken, ip, ua, country) {
			token, err := s.createMFAChallenge(ctx, u.ID, u.TenantID, nil)
			if err != nil {
				return nil, err
			}
			return &LoginSessionResult{MFARequired: true, MFAToken: token, Methods: []string{"totp", "recovery_code"}}, nil
		}
	}
	raw, err := s.CreateLoginSession(ctx, u.ID, ip, ua)
	if err != nil {
		return nil, err
	}
	return &LoginSessionResult{UserID: u.ID, RawCookie: raw}, nil
}

// deviceTrusted reports whether the second factor may be skipped for this login:
// only when the tenant has opted into adaptive MFA AND the request carries a
// live trusted-device token bound to this user AND the risk level is not too
// high. Any failure or missing piece returns false — the safe default is always
// to require MFA.
func (s *Service) deviceTrusted(ctx context.Context, userID, tenantID uuid.UUID, trustedToken, ip, ua, country string) bool {
	if s.devicePolicy == nil || trustedToken == "" {
		return false
	}
	enabled, err := s.devicePolicy.RememberDeviceEnabled(ctx, tenantID)
	if err != nil || !enabled {
		return false
	}
	// A high-risk request (bot-like UA, impossible travel, or an unrecognized
	// device — whichever the tenant has opted into) forces MFA even on a
	// trusted device.
	if s.riskAssessor != nil && s.riskAssessor.ShouldForceMFA(ctx, tenantID, userID, ip, ua, country) {
		return false
	}
	return s.IsTrustedDevice(ctx, userID, trustedToken)
}

// RegisterInTenant creates a new end-user in the given tenant from the hosted
// signup flow and signs them in by minting the SSO session cookie value. It is
// gated by the tenant's self_registration_enabled policy and validates the
// password against that tenant's policy (length/complexity + breach). Returns
// the created user and the raw cookie value to write via SetLoginSessionCookie.
func (s *Service) RegisterInTenant(ctx context.Context, tenantID uuid.UUID, email, plain, displayName, ip, ua string) (*user.User, string, error) {
	if s.regPolicy == nil {
		return nil, "", errs.ErrNotImplemented
	}
	enabled, err := s.regPolicy.SelfRegistrationEnabled(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	if !enabled {
		return nil, "", errs.ErrForbidden.
			WithMessage("Self-registration is not enabled for this application.").
			WithDetail("self-registration disabled")
	}
	// Offline strength baseline (denylist, equals-email, sequential), then the
	// tenant policy (length/complexity) and the breach gate inside ValidateForTenant.
	if reason := password.WeakReason(plain, email); reason != "" {
		return nil, "", errs.ErrUnprocessable.WithMessage(reason)
	}
	if err := s.regPolicy.ValidateForTenant(ctx, tenantID, plain); err != nil {
		return nil, "", err
	}
	hash, err := password.Hash(plain)
	if err != nil {
		return nil, "", err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
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
			return nil, "", errs.ErrConflict.WithDetail("email already exists")
		}
		return nil, "", err
	}
	if err := s.q.WithTx(tx).InsertPasswordCredential(ctx, dbgen.InsertPasswordCredentialParams{
		UserID:       u.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}

	raw, err := s.CreateLoginSession(ctx, u.ID, ip, ua)
	if err != nil {
		return nil, "", err
	}
	return u, raw, nil
}

// createMFAChallenge records a single-use, short-lived pending login that
// CompleteMFALogin later exchanges for tokens. claims (nilable) are any
// Auth-Hook-issued custom claims to carry across the MFA step into the
// eventual access token. Returns the opaque token id.
func (s *Service) createMFAChallenge(ctx context.Context, userID, tenantID uuid.UUID, claims map[string]any) (string, error) {
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	var claimsArg any
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		claimsArg = raw
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth.mfa_login_challenges (user_id, tenant_id, expires_at, claims)
		VALUES ($1, $2, $3, $4) RETURNING id
	`, userID, tid, time.Now().UTC().Add(mfaChallengeTTL), claimsArg).Scan(&id)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// verifyAndConsumeMFAChallenge validates a pending MFA login challenge and its
// second-factor code. On a correct code it consumes (deletes) the challenge
// and returns the user, its tenant (uuid.Nil for a tenant-less challenge), and
// any claims stashed by createMFAChallenge. A wrong code is rejected WITHOUT
// consuming the challenge so the user can retry within the TTL. Shared by the
// token flow (CompleteMFALogin) and the hosted cookie flow
// (CompleteMFALoginSession).
func (s *Service) verifyAndConsumeMFAChallenge(ctx context.Context, mfaToken, code string) (uuid.UUID, uuid.UUID, map[string]any, error) {
	if s.mfa == nil {
		return uuid.Nil, uuid.Nil, nil, errs.ErrNotImplemented
	}
	id, err := uuid.Parse(mfaToken)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, errs.ErrBadRequest.WithDetail("invalid mfa_token")
	}
	var userID uuid.UUID
	var tenantID *uuid.UUID
	var expiresAt time.Time
	var rawClaims []byte
	err = s.pool.QueryRow(ctx, `
		SELECT user_id, tenant_id, expires_at, claims FROM auth.mfa_login_challenges WHERE id = $1
	`, id).Scan(&userID, &tenantID, &expiresAt, &rawClaims)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, nil, errs.ErrUnauthorized.WithMessage("Your sign-in session expired. Please sign in again.").WithDetail("mfa challenge not found")
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	if time.Now().After(expiresAt) {
		_ = s.q.DeleteMFALoginChallenge(ctx, id)
		return uuid.Nil, uuid.Nil, nil, errs.ErrUnauthorized.WithMessage("Your sign-in session expired. Please sign in again.").WithDetail("mfa challenge expired")
	}
	ok, err := s.mfa.VerifyForLogin(ctx, userID, code)
	if err != nil {
		return uuid.Nil, uuid.Nil, nil, err
	}
	if !ok {
		return uuid.Nil, uuid.Nil, nil, errs.ErrUnauthorized.WithMessage("Invalid verification code.").WithDetail("invalid mfa code")
	}
	// Consume the challenge only on success.
	_ = s.q.DeleteMFALoginChallenge(ctx, id)
	var tid uuid.UUID
	if tenantID != nil {
		tid = *tenantID
	}
	var claims map[string]any
	if len(rawClaims) > 0 {
		_ = json.Unmarshal(rawClaims, &claims)
	}
	return userID, tid, claims, nil
}

// CompleteMFALogin verifies the second-factor code for a pending token-flow
// login and, on success, issues the token pair.
func (s *Service) CompleteMFALogin(ctx context.Context, mfaToken, code, ip, ua string) (*TokenPair, error) {
	userID, tid, claims, err := s.verifyAndConsumeMFAChallenge(ctx, mfaToken, code)
	if err != nil {
		return nil, err
	}
	return s.IssuePairWithClaims(ctx, userID, tid, ip, ua, "password_mfa", claims)
}

// CompleteMFALoginSession verifies the second-factor code for a pending
// hosted-login challenge and, on success, mints the SSO session cookie value
// (the cookie-flow analogue of CompleteMFALogin). Returns the user id, its
// tenant (uuid.Nil when tenant-less), and the raw cookie value to write via
// SetLoginSessionCookie.
func (s *Service) CompleteMFALoginSession(ctx context.Context, mfaToken, code, ip, ua string) (uuid.UUID, uuid.UUID, string, error) {
	// Any hook claims stashed on the challenge are discarded here — see the
	// note in BeginLoginSession on why this cookie flow doesn't carry them.
	userID, tid, _, err := s.verifyAndConsumeMFAChallenge(ctx, mfaToken, code)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	raw, err := s.CreateLoginSession(ctx, userID, ip, ua)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	return userID, tid, raw, nil
}

// CheckPassword runs the full credential check — brute-force lockout, user
// lookup, password verify, transparent Argon2id rehash-on-login, and
// clear-on-success — returning the authenticated user plus any custom claims
// a wired Auth Hook asked to be injected into the eventual access token
// (nil when no hook is wired, or the hook returned none). Shared by API login
// (which then issues tokens) and the hosted-login SSO session (which sets a
// cookie). It deliberately does not mint tokens or sessions itself.
func (s *Service) CheckPassword(ctx context.Context, rawEmail, plain string) (*user.User, map[string]any, error) {
	email := strings.ToLower(strings.TrimSpace(rawEmail))
	if _, locked := s.loginLockedUntil(ctx, email); locked {
		return nil, nil, errs.ErrTooManyRequests.
			WithMessage("Too many failed attempts. Your account is temporarily locked — please try again later.").
			WithDetail("account temporarily locked")
	}
	u, err := s.users.GetByEmailGlobal(ctx, rawEmail)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			// Throttle unknown emails identically so probing can't distinguish
			// "no such account" from "wrong password" by behaviour.
			s.recordFailedLogin(ctx, email)
			return nil, nil, errs.ErrUnauthorized.WithMessage("Invalid email or password.").WithDetail("invalid credentials")
		}
		return nil, nil, err
	}
	if u.Status != "active" && u.Status != "invited" {
		return nil, nil, errs.ErrForbidden.WithDetail("account " + u.Status)
	}
	hash, err := s.users.PasswordHash(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	if hash == "" || !password.Verify(hash, plain) {
		s.recordFailedLogin(ctx, email)
		return nil, nil, errs.ErrUnauthorized.WithMessage("Invalid email or password.").WithDetail("invalid credentials")
	}
	s.clearLoginAttempts(ctx, email)
	// Transparently upgrade legacy bcrypt / weak-param hashes to current
	// Argon2id on a successful login. Best-effort: never fail the login on it.
	if password.NeedsRehash(hash) {
		if nh, herr := password.Hash(plain); herr == nil {
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent)
		VALUES ($1, $2, $3, NULLIF($4,'')::inet, $5)
	`, sessionID, userID, tenantArg, ipArg, ua); err != nil {
		return nil, err
	}
	access, exp, err := s.tokens.IssueAccessClaims(userID, tenantID, sessionID, "", claims)
	if err != nil {
		return nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	refreshExp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	if _, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: refreshHash,
		ExpiresAt: refreshExp,
	}); err != nil {
		return nil, err
	}
	if method == "" {
		method = "unknown"
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
		Metadata:     map[string]any{"method": method},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		RefreshToken: refreshRaw,
		SessionID:    sessionID,
		UserID:       userID,
		TenantID:     tenantPtr,
	}, nil
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
	)
	row := tx.QueryRow(ctx, `
		SELECT rt.id, rt.session_id, rt.used_at, rt.expires_at,
		       s.revoked_at, s.user_id, s.tenant_id, u.status, u.deleted_at
		FROM auth.refresh_tokens rt
		JOIN auth.sessions s ON s.id = rt.session_id
		JOIN "user".users u ON u.id = s.user_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt
	`, hash)
	if err := row.Scan(&id, &sessionID, &usedAt, &expiresAt, &sessionRev, &userID, &tenantPtr, &userStatus, &userDeleted); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized.WithDetail("unknown refresh token")
		}
		return nil, err
	}
	if sessionRev != nil {
		return nil, errs.ErrUnauthorized.WithDetail("session revoked")
	}
	// A session can outlive the account it belongs to: a plain status
	// change (PATCH /users/{id}) or a soft-delete doesn't touch
	// auth.sessions at all, so without this check a suspended/deleted
	// user's still-valid refresh token would keep minting fresh access
	// tokens indefinitely.
	if userDeleted != nil || userStatus == "suspended" {
		return nil, errs.ErrUnauthorized.WithDetail("account suspended or deleted")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("refresh token expired")
	}
	// uuid.Nil = tenant-less session; preserved across refresh.
	var tenantID uuid.UUID
	if tenantPtr != nil {
		tenantID = *tenantPtr
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
		// Best-effort, outside the transaction: the revocation is already
		// durable at this point, and webhook.Service.Enqueue does its own
		// pool calls — it can't join the tx above.
		s.emit(ctx, tenantID, "session.revoked", map[string]any{
			"user_id":    userID,
			"session_id": sessionID,
			"reason":     "reuse_detected",
			"revoked_at": time.Now().UTC(),
		})
		return nil, errs.ErrUnauthorized.WithDetail("refresh token reuse — session revoked")
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	newExp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	newID, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: newHash,
		ExpiresAt: newExp,
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
	if err := s.q.WithTx(tx).UpdateSessionLastSeen(ctx, sessionID); err != nil {
		return nil, err
	}
	access, exp, err := s.tokens.IssueAccess(userID, tenantID, sessionID, "")
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresAt:    exp,
		RefreshToken: newRaw,
		SessionID:    sessionID,
		UserID:       userID,
		TenantID:     tenantPtr,
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
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	var userID uuid.UUID
	var tenantID *uuid.UUID
	err := s.pool.QueryRow(ctx, `
		UPDATE auth.sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL
		RETURNING user_id, tenant_id
	`, sessionID).Scan(&userID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if tenantID != nil {
		s.emit(ctx, *tenantID, "session.revoked", map[string]any{
			"user_id":    userID,
			"session_id": sessionID,
			"reason":     "logout",
			"revoked_at": time.Now().UTC(),
		})
	}
	return nil
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
}

func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	// Soft-deleted users keep their session rows for audit purposes but
	// must not surface them via admin or self-service listings. Filter
	// at the join rather than relying on the caller to know about
	// `users.deleted_at`.
	rows, err := s.pool.Query(ctx, `
		SELECT sess.id, sess.user_id, sess.tenant_id, host(sess.ip), sess.user_agent,
		       sess.created_at, sess.last_seen_at, sess.revoked_at
		FROM auth.sessions sess
		JOIN "user".users u ON u.id = sess.user_id
		WHERE sess.user_id = $1 AND u.deleted_at IS NULL
		ORDER BY sess.created_at DESC
		LIMIT 100
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TenantID, &s.IP, &s.UserAgent, &s.CreatedAt, &s.LastSeenAt, &s.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
