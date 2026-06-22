// Package invite lets a tenant admin invite an email address into a
// tenant with a pre-assigned role. The invitee follows the link, creates
// their account, and the invite is consumed in the same transaction.
package invite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/codes"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/hibp"
	"github.com/qeetgroup/qeet-id/platform/notifier"
	"github.com/qeetgroup/qeet-id/platform/password"
)

type Invite struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Email      string     `json:"email"`
	RoleID     *uuid.UUID `json:"role_id"`
	Status     string     `json:"status"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type CreateInput struct {
	TenantID uuid.UUID  `json:"tenant_id" validate:"required"`
	Email    string     `json:"email" validate:"required,email"`
	RoleID   *uuid.UUID `json:"role_id"`
}

type Service struct {
	pool       *pgxpool.Pool
	sender     notifier.Sender
	ttl        time.Duration
	baseAppURL string
	// breach is the optional breached-password checker (nil = feature off, a
	// no-op). Set via SetBreachChecker; consulted on Accept.
	breach *hibp.Checker
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration, baseAppURL string) *Service {
	if ttl <= 0 {
		ttl = 14 * 24 * time.Hour
	}
	return &Service{pool: pool, sender: sender, ttl: ttl, baseAppURL: baseAppURL}
}

// SetBreachChecker wires the breached-password checker. Called from
// cmd/server/main.go only when BREACHED_PASSWORD_CHECK is enabled.
func (s *Service) SetBreachChecker(c *hibp.Checker) { s.breach = c }

func (s *Service) Create(ctx context.Context, in CreateInput, invitedBy *uuid.UUID) (*Invite, string, error) {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().UTC().Add(s.ttl)
	row := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.invites (tenant_id, email, role_id, invited_by, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at
	`, in.TenantID, in.Email, in.RoleID, invitedBy, hash, expires)
	var iv Invite
	if err := row.Scan(&iv.ID, &iv.TenantID, &iv.Email, &iv.RoleID, &iv.Status, &iv.ExpiresAt, &iv.AcceptedAt, &iv.CreatedAt); err != nil {
		return nil, "", err
	}
	_ = s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      in.Email,
		Subject: "You've been invited to Qeet",
		Body:    fmt.Sprintf("Accept the invite: %s/invite/accept?token=%s", s.baseAppURL, raw),
	})
	return &iv, raw, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Invite, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, email, role_id, status, expires_at, accepted_at, created_at
		FROM tenant.invites
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 200
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var iv Invite
		if err := rows.Scan(&iv.ID, &iv.TenantID, &iv.Email, &iv.RoleID, &iv.Status, &iv.ExpiresAt, &iv.AcceptedAt, &iv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, iv)
	}
	return out, nil
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE tenant.invites SET status = 'revoked'
		WHERE id = $1 AND status = 'pending'
	`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type AcceptInput struct {
	Token       string `json:"token" validate:"required"`
	Password    string `json:"password" validate:"required,min=8"`
	DisplayName string `json:"display_name" validate:"omitempty,max=200"`
}

type AcceptResult struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
}

func (s *Service) Accept(ctx context.Context, in AcceptInput) (*AcceptResult, error) {
	// Breached-password gate before any DB work. No-op when disabled (nil
	// checker) and fail-open inside PwnedAllowOnError.
	if s.breach.PwnedAllowOnError(ctx, in.Password) {
		return nil, errs.ErrUnprocessable.WithDetail("This password has appeared in known data breaches — choose a different one.")
	}
	hash := codes.Hash(in.Token)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		id        uuid.UUID
		tenantID  uuid.UUID
		email     string
		roleID    *uuid.UUID
		status    string
		expiresAt time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, email, role_id, status, expires_at
		FROM tenant.invites
		WHERE token_hash = $1
		FOR UPDATE
	`, hash).Scan(&id, &tenantID, &email, &roleID, &status, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrBadRequest.WithDetail("invalid token")
		}
		return nil, err
	}
	if status != "pending" {
		return nil, errs.ErrBadRequest.WithDetail("invite " + status)
	}
	if time.Now().After(expiresAt) {
		_, _ = tx.Exec(ctx, `UPDATE tenant.invites SET status = 'expired' WHERE id = $1`, id)
		_ = tx.Commit(ctx)
		return nil, errs.ErrBadRequest.WithDetail("invite expired")
	}

	pwHash, err := password.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, display_name, status, email_verified_at)
		VALUES ($1, $2, NULLIF($3,''), 'active', NOW())
		RETURNING id
	`, tenantID, email, in.DisplayName).Scan(&userID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)
	`, userID, pwHash); err != nil {
		return nil, err
	}
	if roleID != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)
		`, userID, tenantID, *roleID); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tenant.invites SET status = 'accepted', accepted_at = NOW() WHERE id = $1
	`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AcceptResult{UserID: userID, TenantID: tenantID}, nil
}
