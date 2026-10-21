// Package recovery handles forgot-password and magic-link login.
// Both are stateless tokens: the user clicks a link, we look up the
// hash, and either reset their password or issue a session.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/recovery/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// AuditCtx carries the per-request client context recovery handlers
// thread into the service so the audit row can attribute the action.
// These flows have no authenticated principal (they're token-based)
// so the actor for the audit row is the user being acted upon.
type AuditCtx struct {
	IP        string
	UserAgent string
	RequestID string
}

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	sender notifier.Sender
	ttl    time.Duration
	// baseAppURL is the console origin: the default target of email links
	// (password reset, magic link), completed in the console itself.
	baseAppURL string
	// loginBaseURL is the hosted login origin (LOGIN_BASE_URL). A reset
	// requested from hosted login links to its own reset page. Empty = off
	// (every reset link uses the console). Set via SetHostedLogin.
	loginBaseURL string
	// rules checks a new password on ConfirmPasswordReset (nil = resets are
	// refused rather than set an unchecked password). Set via SetPasswordRules.
	rules PasswordRules
	// magicLinks decides whether an organisation allows magic links and how
	// long they live (nil = allowed, the default lifetime). Set via
	// SetMagicLinkPolicy.
	magicLinks MagicLinkPolicy
	// magicPerAddress and magicPerCaller bound magic-link requests (nil =
	// unbounded). Set via SetMagicLinkLimits; see magiclink.go.
	magicPerAddress Limiter
	magicPerCaller  Limiter
	// signals announces ended sessions (nil = announces nothing). Set via
	// SetSessionSignals.
	signals *sessionsignal.Signaller
}

// PasswordRules is the one password check every path that sets a password
// runs: the rules of the organisation the account belongs to (uuid.Nil = none:
// the platform baseline), the offline strength baseline and, when enabled,
// the breach check. Satisfied by *authpolicy.Service; an interface so recovery
// doesn't import it.
type PasswordRules interface {
	ValidateForTenant(ctx context.Context, tenantID uuid.UUID, email, pw string) error
}

// MagicLinkPolicy is the slice of the authentication policy that decides
// whether an organisation allows magic-link sign-in and how long its links
// live. Satisfied by *authpolicy.Service.
type MagicLinkPolicy interface {
	MagicLinkPolicy(ctx context.Context, tenantID uuid.UUID) (enabled bool, ttl time.Duration, err error)
}

// SetSessionSignals wires the announcement of ended sessions. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// SetMagicLinkPolicy wires the magic-link policy. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetMagicLinkPolicy(p MagicLinkPolicy) { s.magicLinks = p }

// magicLinkTTL is how long a magic link for tenantID lives, or
// ErrAuthMethodDisabled when the tenant has switched magic links off
// (uuid.Nil: no organisation, the platform default).
func (s *Service) magicLinkTTL(ctx context.Context, tenantID uuid.UUID) (time.Duration, error) {
	// No organisation, no organisation policy: the platform allows magic
	// links, with the default lifetime.
	if s.magicLinks == nil || tenantID == uuid.Nil {
		return s.ttl, nil
	}
	enabled, ttl, err := s.magicLinks.MagicLinkPolicy(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	if !enabled {
		return 0, errs.ErrAuthMethodDisabled
	}
	if ttl <= 0 {
		return s.ttl, nil
	}
	return ttl, nil
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, baseAppURL string) *Service {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl, baseAppURL: baseAppURL}
}

// SetPasswordRules wires the password check run on reset. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetPasswordRules(r PasswordRules) { s.rules = r }

// SetHostedLogin wires the hosted login origin, so a reset requested there
// links back to its own reset page. Called from internal/bootstrap/dependencies.go.
func (s *Service) SetHostedLogin(loginBaseURL string) { s.loginBaseURL = loginBaseURL }

// AppHostedLogin marks a reset requested from the hosted login (ResetOrigin.App).
const AppHostedLogin = "hosted_login"

// ResetOrigin says where a password reset was requested from, which decides
// where its emailed link lands.
type ResetOrigin struct {
	// App is AppHostedLogin for the hosted login. Anything else, or empty,
	// means the console — the documented default.
	App string
	// ReturnTo (hosted login only) is where to continue after the reset. The
	// caller must already have validated it; it is passed through as given.
	ReturnTo string
}

// resetLink builds the emailed reset link: hosted login's own reset page for a
// reset requested there, the console's reset screen otherwise. The token goes
// last, after any return_to.
func (s *Service) resetLink(raw string, from ResetOrigin) string {
	if from.App == AppHostedLogin && s.loginBaseURL != "" {
		q := url.Values{}
		if from.ReturnTo != "" {
			q.Set("return_to", from.ReturnTo)
		}
		prefix := ""
		if len(q) > 0 {
			prefix = q.Encode() + "&"
		}
		return fmt.Sprintf("%s/reset?%stoken=%s", s.loginBaseURL, prefix, url.QueryEscape(raw))
	}
	return fmt.Sprintf("%s/forgot-password?token=%s", s.baseAppURL, raw)
}

// StartPasswordReset issues a reset token for the account with this email, if
// one exists. It always succeeds from the caller's perspective so it never
// leaks whether an email is registered. Look-up is by email *globally* — email
// is unique platform-wide and sign-in is tenant-less (migration 0022), so a
// tenant-scoped lookup would never match a request from the tenant-less sign-in
// page. Returns the raw token so a dev-mode handler can surface the reset link
// in local development; the token is empty when no account matched (or on error).
func (s *Service) StartPasswordReset(ctx context.Context, email string) (string, error) {
	return s.StartPasswordResetFrom(ctx, email, ResetOrigin{})
}

// StartPasswordResetFrom is StartPasswordReset for a reset requested from a
// given application: the emailed link lands back there (see resetLink).
func (s *Service) StartPasswordResetFrom(ctx context.Context, email string, from ResetOrigin) (string, error) {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`, email,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if err := s.q.InsertPasswordReset(ctx, dbgen.InsertPasswordResetParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}); err != nil {
		return "", err
	}
	resetURL := s.resetLink(raw, from)
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Reset your password",
		Body:    fmt.Sprintf("Reset your Qeet ID password: %s", resetURL),
		HTML: emailtmpl.Action(
			"Reset your password",
			"We received a request to reset the password for your Qeet ID account. Click the button below to choose a new one.",
			"Reset password", resetURL,
			"If you didn't request a password reset, you can safely ignore this email — your password won't change.",
		),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// ConfirmPasswordReset sets a new password with a reset link. The password is
// checked against the rules of the organisation the account belongs to (or
// the platform baseline for a tenant-less account) once the link is known to
// be good — the account, and so its rules, comes from the link. A refused
// password leaves the credential and the link untouched.
func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string, ac AuditCtx) error {
	if s.rules == nil {
		return errs.ErrNotImplemented
	}
	hash := codes.Hash(rawToken)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	qtx := s.q.WithTx(tx)
	row, err := qtx.GetPasswordResetByToken(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrResetLinkInvalid
		}
		return err
	}
	if row.UsedAt.Valid {
		return errs.ErrRecoveryLinkUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrRecoveryLinkExpired
	}
	account, err := qtx.GetResetAccount(ctx, row.UserID)
	if err != nil {
		return err
	}
	var tenantID uuid.UUID // uuid.Nil: the account belongs to no organisation
	if account.TenantID.Valid {
		tenantID = account.TenantID.Bytes
	}
	if err := s.rules.ValidateForTenant(ctx, tenantID, account.Email, newPassword); err != nil {
		return err
	}
	pwHash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := qtx.UpsertPasswordCredential(ctx, dbgen.UpsertPasswordCredentialParams{
		UserID:       row.UserID,
		PasswordHash: pwHash,
	}); err != nil {
		return err
	}
	if err := qtx.MarkPasswordResetUsed(ctx, row.ID); err != nil {
		return err
	}
	// The link reached the address and nobody else: it proves the address,
	// so an account registered with it unproved becomes the owner's here —
	// its old password and every session it had end below.
	verifiedEmail, err := qtx.VerifyEmailByReset(ctx, row.UserID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	default:
		verifiedID := row.UserID
		if err := audit.Record(ctx, tx, audit.Event{
			ActorUserID:  &verifiedID,
			ActorType:    "user",
			Action:       "email.verified",
			ResourceType: "user",
			ResourceID:   &verifiedID,
			IP:           ac.IP,
			UserAgent:    ac.UserAgent,
			RequestID:    ac.RequestID,
			Metadata:     map[string]any{"email": verifiedEmail, "proof": "password_reset"},
		}); err != nil {
			return err
		}
	}
	// Invalidate all existing sessions on password reset, and announce them.
	ended, err := sessionsignal.EndUserSessions(ctx, tx, row.UserID)
	if err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonPasswordReset, ended...)
	userID := row.UserID
	target := userID
	if err := audit.Record(ctx, tx, audit.Event{
		ActorUserID:  &target,
		ActorType:    "system",
		Action:       "auth.password_reset_confirmed",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           ac.IP,
		UserAgent:    ac.UserAgent,
		RequestID:    ac.RequestID,
		Metadata:     map[string]any{"sessions_revoked": true},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
