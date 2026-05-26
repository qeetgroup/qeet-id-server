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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/notifier"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
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
	sender     notifier.Sender
	ttl        time.Duration
	baseAppURL string // e.g. "https://app.qeet.com" — used to build links
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, baseAppURL string) *Service {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Service{pool: pool, sender: sender, ttl: ttl, baseAppURL: baseAppURL}
}

// StartPasswordReset always succeeds from the caller's perspective so we
// don't leak whether an email is registered.
func (s *Service) StartPasswordReset(ctx context.Context, tenantID uuid.UUID, email string) error {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM "user".users
		WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL
	`, tenantID, email).Scan(&userID)
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
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.password_resets (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, hash, time.Now().UTC().Add(s.ttl)); err != nil {
		return err
	}
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Reset your password",
		Body:    fmt.Sprintf("Click to reset: %s/reset?token=%s", s.baseAppURL, raw),
	})
}

func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string, ac AuditCtx) error {
	if len(newPassword) < 8 {
		return errs.ErrUnprocessable.WithDetail("password too short")
	}
	hash := codes.Hash(rawToken)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var id, userID uuid.UUID
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, user_id, expires_at, used_at
		FROM auth.password_resets
		WHERE token_hash = $1
		FOR UPDATE
	`, hash).Scan(&id, &userID, &expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrBadRequest.WithDetail("invalid token")
		}
		return err
	}
	if usedAt != nil {
		return errs.ErrBadRequest.WithDetail("token already used")
	}
	if time.Now().After(expiresAt) {
		return errs.ErrBadRequest.WithDetail("token expired")
	}
	pwHash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
	`, userID, pwHash); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.password_resets SET used_at = NOW() WHERE id = $1`, id); err != nil {
		return err
	}
	// Invalidate all existing sessions on password reset.
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
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
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.magic_links (tenant_id, email, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, tenantID, email, hash, time.Now().UTC().Add(s.ttl)); err != nil {
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

	hash := codes.Hash(rawToken)
	var id uuid.UUID
	var tenantID uuid.UUID
	var email string
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, email, expires_at, used_at
		FROM auth.magic_links
		WHERE token_hash = $1
		FOR UPDATE
	`, hash).Scan(&id, &tenantID, &email, &expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrBadRequest.WithDetail("invalid token")
		}
		return nil, err
	}
	if usedAt != nil {
		return nil, errs.ErrBadRequest.WithDetail("token already used")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("token expired")
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM "user".users
		WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL
	`, tenantID, email).Scan(&userID)
	if err != nil {
		return nil, errs.ErrNotFound.WithDetail("no user for email")
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.magic_links SET used_at = NOW() WHERE id = $1`, id); err != nil {
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
