package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// LoginInput is what Login takes.
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
	// UserAgent is the browser's, for the record of a failed attempt.
	UserAgent string
}

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

// Login verifies the password and, when the account holds a second factor or
// must have one (see mfapolicy.go), returns an MFA challenge instead of tokens
// (complete it via CompleteMFALoginWith). Otherwise it returns a full token
// pair.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	u, claims, err := s.CheckPassword(ctx, SignInAttempt{Email: in.Email, Password: in.Password, IP: in.IP, UserAgent: in.UserAgent})
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
	s.recordSignIn(ctx, u.ID, u.TenantID, in.UserAgent, httpx.GeoCountry(ctx))
	return &LoginResult{Pair: pair}, nil
}

// BeginLoginSession is the hosted-login (cookie) form of Login. It verifies the
// password and returns an MFA challenge when the account needs a second factor,
// or the SSO session cookie value otherwise.
func (s *Service) BeginLoginSession(ctx context.Context, in SignInAttempt, ua, trustedToken, country string) (*LoginSessionResult, error) {
	// Hook claims don't apply here: the SSO cookie is opaque, and tokens are
	// minted later by the OIDC authorize flow. The application's organisation
	// applies its address rules before the password is checked, so the answer is
	// the same whether the password is right or wrong.
	clientTenant, err := s.SignInTenant(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	if err := s.checkAddress(ctx, clientTenant, uuid.Nil, in.IP, "hosted_password"); err != nil {
		return nil, err
	}
	in.UserAgent = ua
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
	s.recordSignIn(ctx, u.ID, u.TenantID, ua, country)
	return &LoginSessionResult{UserID: u.ID, RawCookie: raw}, nil
}

// CheckPassword runs the full password check (lockout, lookup, verification and
// Argon2id rehash) and returns the user and any hook claims for the access
// token. It does not create tokens or sessions.
func (s *Service) CheckPassword(ctx context.Context, in SignInAttempt) (*user.User, map[string]any, error) {
	// A hosted login names the application, so its organisation decides whether
	// password sign-in is allowed before the password is checked. Otherwise the
	// account's own organisation decides after verification.
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
	failure := SignInFailure{TenantID: signInTenant, Method: "password", IP: in.IP, UserAgent: in.UserAgent}
	owner := func() uuid.UUID {
		if locked, err := s.users.GetByEmailGlobal(ctx, in.Email); err == nil {
			return locked.ID
		}
		return uuid.Nil
	}
	if err := s.refuseLocked(ctx, attempt, failure, owner); err != nil {
		return nil, nil, err
	}
	u, err := s.users.GetByEmailGlobal(ctx, in.Email)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			// No such account: spend a password verification and count the
			// failure exactly as for a wrong password, so neither the answer,
			// its timing nor the lockout tells the two apart. Its record
			// names no person.
			if _, err := verifyPassword(ctx, "", in.Password); err != nil {
				return nil, nil, err
			}
			failure.Reason = FailureUnknownAccount
			if err := s.recordFailedSignIn(ctx, attempt, failure); err != nil {
				return nil, nil, err
			}
			return nil, nil, errs.ErrAuthInvalidCredentials
		}
		return nil, nil, err
	}
	hash, err := s.users.PasswordHash(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	ok, err := verifyPassword(ctx, hash, in.Password)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		failure.UserID, failure.Reason = u.ID, FailureWrongPassword
		if err := s.recordFailedSignIn(ctx, attempt, failure); err != nil {
			return nil, nil, err
		}
		return nil, nil, errs.ErrAuthInvalidCredentials
	}
	// Only the right password learns the account's status, so a wrong one
	// answers the same for every address.
	if u.Status != "active" && u.Status != "invited" {
		return nil, nil, errs.ErrAuthAccountInactive
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
	hookTenant := signInTenant
	if hookTenant == uuid.Nil {
		hookTenant = u.TenantID
	}
	claims, err := s.hookClaims(ctx, hookTenant, u)
	if err != nil {
		return nil, nil, err
	}
	return u, claims, nil
}

// ChangePasswordInput is what ChangePassword takes.
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

// ChangePassword updates the password, ends every other session, hosted-login
// session, remembered device and application grant, and records audit evidence
// in one transaction; the current session stays. The new password is checked
// against the account's organisation's rules before the current one is verified.
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
	// Every other way in too: the calling session is an API one, kept above.
	ended, err := endOtherSignIns(ctx, tx, in.UserID)
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: in.TenantID, ActorUserID: &in.UserID, ActorType: "user",
		Action: "auth.password_changed", ResourceType: "user", ResourceID: &in.UserID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: map[string]any{
			"revoked_sessions": revoked, "revoked_login_sessions": ended.LoginSessions,
			"revoked_app_grants": ended.AppGrants, "revoked_trusted_devices": ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations, "kept_session_id": in.KeepSessionID,
		},
	}); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: in.UserID, Topic: "user.events", EventType: "auth.password_changed",
		Payload: map[string]any{
			"user_id": in.UserID, "tenant_id": in.TenantID,
			"kept_session_id": in.KeepSessionID, "revoked_sessions": revoked, "revoked_login_sessions": ended.LoginSessions,
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
