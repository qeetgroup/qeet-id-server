package authentication

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/accountnotice"
	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// LoginInput is what Login takes. Its Actor is the client's address and user
// agent.
type LoginInput struct {
	Email    string
	Password string
	audit.Actor
}

// SignInAttempt is one password sign-in as the API received it.
type SignInAttempt struct {
	Email    string
	Password string
	// ClientID is the OAuth client a hosted login is serving ("" = none). Its
	// organization's lockout settings apply (see SignInOrganization).
	ClientID string
	// Actor is the client: its IP as httpx.ClientIP derives it, whose network
	// keys the lockout counters ("" when unknown), and its user agent and the
	// request ID, for the record of a failed attempt.
	audit.Actor
}

// passwordAllowed refuses with ErrAuthMethodDisabled when organizationID has switched
// password sign-in off. uuid.Nil (no organization) is not restricted.
func (s *Service) passwordAllowed(ctx context.Context, organizationID uuid.UUID) error {
	if organizationID == uuid.Nil {
		return nil
	}
	enabled, err := s.methods.PasswordEnabled(ctx, organizationID)
	if err != nil {
		return err
	}
	if !enabled {
		return errs.ErrAuthMethodDisabled
	}
	return nil
}

// checkNewPassword runs the password check for an account in organizationID
// (uuid.Nil = no organization).
func (s *Service) checkNewPassword(ctx context.Context, organizationID uuid.UUID, email, plain string) error {
	return s.regPolicy.ValidateForOrganization(ctx, organizationID, email, plain)
}

// Login verifies the password and, when the account holds a second factor or
// must have one (see mfapolicy.go), returns an MFA challenge instead of tokens
// (complete it via CompleteMFALoginWith). Otherwise it returns a full token
// pair.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	u, claims, err := s.CheckPassword(ctx, SignInAttempt{Email: in.Email, Password: in.Password, Actor: in.Actor})
	if err != nil {
		return nil, err
	}
	gate, err := s.mfaGate(ctx, u.ID, u.OrganizationID)
	if err != nil {
		return nil, err
	}
	switch s.nextSignInStep(ctx, u.ID, u.OrganizationID, gate, firstFactorPassword, "", in.IP, in.UserAgent, httpx.GeoCountry(ctx)) {
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, u.ID, u.OrganizationID, claims, gate, firstFactorPassword, in.IP, in.UserAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, u.ID, u.OrganizationID, claims, firstFactorPassword, in.IP, in.UserAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePairWithClaims(ctx, u.ID, u.OrganizationID, in.IP, in.UserAgent, "password", claims)
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, u.ID, u.OrganizationID, in.UserAgent, httpx.GeoCountry(ctx))
	return &LoginResult{Pair: pair}, nil
}

// BeginLoginSession is the hosted-login (cookie) form of Login. It verifies the
// password and returns an MFA challenge when the account needs a second factor,
// or the SSO session cookie value otherwise.
func (s *Service) BeginLoginSession(ctx context.Context, in SignInAttempt, ua, trustedToken, country string) (*LoginSessionResult, error) {
	// Hook claims don't apply here: the SSO cookie is opaque, and tokens are
	// minted later by the OIDC authorize flow. The application's organization
	// applies its address rules before the password is checked, so the answer is
	// the same whether the password is right or wrong.
	clientOrganization, err := s.SignInOrganization(ctx, in.ClientID)
	if err != nil {
		return nil, err
	}
	if err := s.checkAddress(ctx, clientOrganization, uuid.Nil, in.IP, "hosted_password"); err != nil {
		return nil, err
	}
	in.UserAgent = ua
	u, _, err := s.CheckPassword(ctx, in)
	if err != nil {
		return nil, err
	}
	// The organization of the application served requires its second factor
	// here as well as the account's own.
	gate, err := s.mfaGateFor(ctx, u.ID, u.OrganizationID, clientOrganization)
	if err != nil {
		return nil, err
	}
	// A trusted device may skip a factor the account holds, never the setting
	// up of one it must have, and never on a risky sign-in. The organization
	// served — the application's, else the account's own — decides, as on the
	// social path, so a device another organization remembers skips nothing.
	served := clientOrganization
	if served == uuid.Nil {
		served = u.OrganizationID
	}
	switch s.nextSignInStep(ctx, u.ID, served, gate, firstFactorPassword, trustedToken, in.IP, ua, country) {
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, u.ID, u.OrganizationID, nil, firstFactorPassword, in.IP, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: u.ID, MFAChallenge: challenge}, nil
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, u.ID, u.OrganizationID, nil, gate, firstFactorPassword, in.IP, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: u.ID, MFAChallenge: challenge}, nil
	}
	if in.ClientID != "" {
		ctx = WithSignInClient(ctx, in.ClientID)
	}
	raw, err := s.createLoginSession(ctx, u.ID, u.OrganizationID, in.IP, ua, firstFactorPassword, gate.skippedFactor())
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, u.ID, u.OrganizationID, ua, country)
	return &LoginSessionResult{UserID: u.ID, RawCookie: raw}, nil
}

// CheckPassword runs the full password check (lockout, lookup, verification and
// Argon2id rehash) and returns the user and any hook claims for the access
// token. It does not create tokens or sessions.
func (s *Service) CheckPassword(ctx context.Context, in SignInAttempt) (*user.User, map[string]any, error) {
	// A hosted login names the application, so its organization decides whether
	// password sign-in is allowed before the password is checked; the account's
	// own organization decides too, after verification.
	signInOrganization, err := s.SignInOrganization(ctx, in.ClientID)
	if err != nil {
		return nil, nil, err
	}
	// An address whose organization requires single sign-on is sent there
	// before any account is looked up, so the answer is the same for every
	// address on the domain, and nothing is counted against the lockout.
	if err := s.refuseCaptured(ctx, in.Email); err != nil {
		return nil, nil, err
	}
	if err := s.passwordAllowed(ctx, signInOrganization); err != nil {
		return nil, nil, err
	}
	attempt, err := s.newSignInAttempt(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	failure := SignInFailure{OrganizationID: signInOrganization, Method: "password", Actor: in.Actor}
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
			return nil, nil, ErrInvalidCredentials
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
		return nil, nil, ErrInvalidCredentials
	}
	// Only the right password learns the account's status, so a wrong one
	// answers the same for every address.
	if u.Status != "active" && u.Status != "invited" {
		return nil, nil, errs.ErrAuthAccountInactive
	}
	if err := s.clearFailedSignIns(ctx, attempt); err != nil {
		return nil, nil, err
	}
	// Whichever application the sign-in named, an organization that switched
	// passwords off keeps its people from signing in with one.
	if u.OrganizationID != signInOrganization {
		if err := s.passwordAllowed(ctx, u.OrganizationID); err != nil {
			return nil, nil, err
		}
	}
	// Upgrade a hash made with weaker Argon2id parameters to the current ones
	// on a successful login. Best-effort: never fail the login on it.
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
	hookOrganization := signInOrganization
	if hookOrganization == uuid.Nil {
		hookOrganization = u.OrganizationID
	}
	claims, err := s.hookClaims(ctx, hookOrganization, u)
	if err != nil {
		return nil, nil, err
	}
	return u, claims, nil
}

// ChangePasswordInput is what ChangePassword takes.
type ChangePasswordInput struct {
	UserID         uuid.UUID
	KeepSessionID  uuid.UUID
	OrganizationID *uuid.UUID
	Current        string
	Next           string
	// Actor is the request's client address, user agent and request ID, for
	// its audit record.
	audit.Actor
}

// ChangePassword updates the password, ends every other session, hosted-login
// session, remembered device and application grant, and records audit evidence
// in one transaction; the current session stays. The new password is checked
// against the account's organization's rules before the current one is verified.
func (s *Service) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	// The account's organization, whose password rules apply, needn't be the
	// one the caller is signed in to.
	ctx = postgres.AcrossOrganizations(ctx)
	account, err := s.users.Get(ctx, in.UserID)
	if err != nil {
		return err
	}
	if err := s.checkNewPassword(ctx, account.OrganizationID, account.Email, in.Next); err != nil {
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
	q := s.q.WithTx(tx)
	if _, err := q.LockAccount(ctx, in.UserID); err != nil {
		return err
	}
	currentHash, err := q.PasswordHash(ctx, in.UserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if currentHash != "" {
		ok, err := password.VerifyWithin(ctx, currentHash, in.Current)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidCredentials
		}
	}
	if err := q.SetPassword(ctx, dbgen.SetPasswordParams{UserID: in.UserID, PasswordHash: nh}); err != nil {
		return err
	}
	rows, err := q.RevokeOtherSessionsForUser(ctx, dbgen.RevokeOtherSessionsForUserParams{
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
	if err := audit.Record(ctx, tx, as(in.Actor, "user", &in.UserID).EventIn(in.OrganizationID, "auth.password_changed", "user", in.UserID,
		map[string]any{
			"revoked_sessions": revoked, "revoked_login_sessions": ended.LoginSessions,
			"revoked_app_grants": ended.AppGrants, "revoked_trusted_devices": ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations, "kept_session_id": in.KeepSessionID,
		})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: in.UserID, Topic: "user.events", EventType: "auth.password_changed",
		Payload: map[string]any{
			"user_id": in.UserID, "organization_id": in.OrganizationID,
			"kept_session_id": in.KeepSessionID, "revoked_sessions": revoked, "revoked_login_sessions": ended.LoginSessions,
		},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	accountnotice.Tell(ctx, s.pool, s.sender, in.UserID, "Your password was changed",
		"A new password was set for your Qeet ID account, and you were signed out everywhere else.")
	return nil
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
	if plain == "" {
		return true, false, nil
	}
	ok, err = password.VerifyWithin(ctx, hash, plain)
	return true, ok, err
}
