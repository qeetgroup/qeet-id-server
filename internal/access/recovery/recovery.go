// Package recovery handles forgot-password and magic-link login.
// Both are stateless tokens: the user clicks a link, we look up the
// hash, and either reset their password or issue a session.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/recovery/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
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
	// baseAppURL is the app origin used to build email links (password reset,
	// magic-link). The link lands back in the app that initiated it, which
	// completes the flow in-place — reset/magic-link are no longer routed to the
	// separate hosted-login app.
	baseAppURL string
	// breach is the optional breached-password checker (nil = feature off, a
	// no-op). Set via SetBreachChecker; consulted on ConfirmPasswordReset.
	breach *hibp.Checker
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, baseAppURL string) *Service {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl, baseAppURL: baseAppURL}
}

// SetBreachChecker wires the breached-password checker. Called from
// cmd/server/main.go only when BREACHED_PASSWORD_CHECK is enabled.
func (s *Service) SetBreachChecker(c *hibp.Checker) { s.breach = c }

// StartPasswordReset issues a reset token for the account with this email, if
// one exists. It always succeeds from the caller's perspective so it never
// leaks whether an email is registered. Look-up is by email *globally* — email
// is unique platform-wide and sign-in is tenant-less (migration 0022), so a
// tenant-scoped lookup would never match a request from the tenant-less sign-in
// page. Returns the raw token so a dev-mode handler can surface the reset link
// in local development; the token is empty when no account matched (or on error).
func (s *Service) StartPasswordReset(ctx context.Context, email string) (string, error) {
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
	// The reset is completed in the console itself (baseAppURL) at
	// /forgot-password?token=…, not the separate hosted-login app.
	resetURL := fmt.Sprintf("%s/forgot-password?token=%s", s.baseAppURL, raw)
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

func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string, ac AuditCtx) error {
	if len(newPassword) < 8 {
		return errs.ErrUnprocessable.WithMessage("Your new password must be at least 8 characters.")
	}
	// Offline strength baseline (common-password denylist, uniform/sequential).
	if reason := password.WeakReason(newPassword, ""); reason != "" {
		return errs.ErrUnprocessable.WithMessage(reason)
	}
	// Breached-password gate before any DB work. No-op when disabled (nil
	// checker) and fail-open inside PwnedAllowOnError.
	if s.breach.PwnedAllowOnError(ctx, newPassword) {
		return errs.ErrUnprocessable.WithMessage("This password has appeared in known data breaches. Choose a different one.")
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
	// Invalidate all existing sessions on password reset.
	if err := qtx.RevokeUserSessions(ctx, row.UserID); err != nil {
		return err
	}
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

// StartMagicLink emits a one-time login link.
func (s *Service) StartMagicLink(ctx context.Context, tenantID uuid.UUID, email string) error {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return err
	}
	if err := s.q.InsertMagicLink(ctx, dbgen.InsertMagicLinkParams{
		TenantID:  tenantID,
		Email:     email,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}); err != nil {
		return err
	}
	magicURL := fmt.Sprintf("%s/magic?token=%s", s.baseAppURL, raw)
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Your login link",
		Body:    fmt.Sprintf("Sign in to Qeet ID: %s", magicURL),
		HTML: emailtmpl.Action(
			"Sign in to Qeet ID",
			"Click the button below to sign in. This link is single-use and expires shortly.",
			"Sign in", magicURL,
			"If you didn't request this link, you can safely ignore this email.",
		),
	})
}

type MagicLinkResult struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
}

// ConsumeMagicLink marks the link used and returns the (user, tenant) pair
// the caller should mint a session for. Returns ErrNotFound if no user
// exists for the email (auto-provision is left to a higher layer).
func (s *Service) ConsumeMagicLink(ctx context.Context, rawToken string, ac AuditCtx) (*MagicLinkResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	qtx := s.q.WithTx(tx)
	hash := codes.Hash(rawToken)
	mlRow, err := qtx.GetMagicLinkByToken(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrMagicLinkInvalid
		}
		return nil, err
	}
	if mlRow.UsedAt.Valid {
		return nil, errs.ErrRecoveryLinkUsed
	}
	if time.Now().After(mlRow.ExpiresAt) {
		return nil, errs.ErrRecoveryLinkExpired
	}
	tenantID := mlRow.TenantID
	email := mlRow.Email
	userID, err := qtx.GetUserIDByEmailForTenant(ctx, dbgen.GetUserIDByEmailForTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Lower:    email,
	})
	if err != nil {
		return nil, errs.ErrNotFound.WithDetail("no user for email")
	}
	if err := qtx.MarkMagicLinkUsed(ctx, mlRow.ID); err != nil {
		return nil, err
	}
	tid := tenantID
	target := userID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &target,
		ActorType:    "system",
		Action:       "auth.magic_link_consumed",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           ac.IP,
		UserAgent:    ac.UserAgent,
		RequestID:    ac.RequestID,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &MagicLinkResult{UserID: userID, TenantID: tenantID}, nil
}
