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

	"github.com/qeetgroup/qeet-id/domains/access/recovery/dbgen"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/api/rest/codes"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/security/hibp"
	"github.com/qeetgroup/qeet-id/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id/platform/security/encryption"
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
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	sender     notifier.Sender
	ttl        time.Duration
	baseAppURL string // e.g. "https://app.qeet.com" — used for magic-link login links
	// loginBaseURL is the hosted-login app origin (qeetid-login). Password-reset
	// is a pure browser credential flow, so its link lands on the hosted login
	// app's /reset page rather than the app origin.
	loginBaseURL string
	// breach is the optional breached-password checker (nil = feature off, a
	// no-op). Set via SetBreachChecker; consulted on ConfirmPasswordReset.
	breach *hibp.Checker
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, baseAppURL, loginBaseURL string) *Service {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl, baseAppURL: baseAppURL, loginBaseURL: loginBaseURL}
}

// SetBreachChecker wires the breached-password checker. Called from
// cmd/server/main.go only when BREACHED_PASSWORD_CHECK is enabled.
func (s *Service) SetBreachChecker(c *hibp.Checker) { s.breach = c }

// StartPasswordReset always succeeds from the caller's perspective so we
// don't leak whether an email is registered.
func (s *Service) StartPasswordReset(ctx context.Context, tenantID uuid.UUID, email string) error {
	userID, err := s.q.GetUserIDByEmailForTenant(ctx, dbgen.GetUserIDByEmailForTenantParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Lower:    email,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return err
	}
	if err := s.q.InsertPasswordReset(ctx, dbgen.InsertPasswordResetParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}); err != nil {
		return err
	}
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Reset your password",
		Body:    fmt.Sprintf("Click to reset: %s/reset?token=%s", s.loginBaseURL, raw),
	})
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
			return errs.ErrBadRequest.WithDetail("invalid token")
		}
		return err
	}
	if row.UsedAt.Valid {
		return errs.ErrBadRequest.WithDetail("token already used")
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrBadRequest.WithDetail("token expired")
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
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Your login link",
		Body:    fmt.Sprintf("Click to sign in: %s/magic?token=%s", s.baseAppURL, raw),
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
			return nil, errs.ErrBadRequest.WithDetail("invalid token")
		}
		return nil, err
	}
	if mlRow.UsedAt.Valid {
		return nil, errs.ErrBadRequest.WithDetail("token already used")
	}
	if time.Now().After(mlRow.ExpiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("token expired")
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
