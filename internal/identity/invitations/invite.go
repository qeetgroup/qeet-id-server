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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invitations/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
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
	q          *dbgen.Queries
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
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl, baseAppURL: baseAppURL}
}

// SetBreachChecker wires the breached-password checker. Called from
// cmd/server/main.go only when BREACHED_PASSWORD_CHECK is enabled.
func (s *Service) SetBreachChecker(c *hibp.Checker) { s.breach = c }

// uuidPtrToPgtype converts a *uuid.UUID to the pgtype.UUID used by generated code.
func uuidPtrToPgtype(p *uuid.UUID) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: [16]byte(*p), Valid: true}
}

// pgtypeToUUIDPtr converts a pgtype.UUID returned by generated code to *uuid.UUID.
func pgtypeToUUIDPtr(p pgtype.UUID) *uuid.UUID {
	if !p.Valid {
		return nil
	}
	uid := uuid.UUID(p.Bytes)
	return &uid
}

// pgtypeToTimePtr converts a pgtype.Timestamptz to *time.Time.
func pgtypeToTimePtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

func inviteFromInsertRow(row dbgen.InsertInviteRow) Invite {
	return Invite{
		ID:         row.ID,
		TenantID:   row.TenantID,
		Email:      row.Email,
		RoleID:     pgtypeToUUIDPtr(row.RoleID),
		Status:     row.Status,
		ExpiresAt:  row.ExpiresAt,
		AcceptedAt: pgtypeToTimePtr(row.AcceptedAt),
		CreatedAt:  row.CreatedAt,
	}
}

func inviteFromListRow(row dbgen.ListInvitesRow) Invite {
	return Invite{
		ID:         row.ID,
		TenantID:   row.TenantID,
		Email:      row.Email,
		RoleID:     pgtypeToUUIDPtr(row.RoleID),
		Status:     row.Status,
		ExpiresAt:  row.ExpiresAt,
		AcceptedAt: pgtypeToTimePtr(row.AcceptedAt),
		CreatedAt:  row.CreatedAt,
	}
}

func (s *Service) Create(ctx context.Context, in CreateInput, invitedBy *uuid.UUID) (*Invite, string, error) {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().UTC().Add(s.ttl)
	row, err := s.q.InsertInvite(ctx, dbgen.InsertInviteParams{
		TenantID:  in.TenantID,
		Email:     in.Email,
		RoleID:    uuidPtrToPgtype(in.RoleID),
		InvitedBy: uuidPtrToPgtype(invitedBy),
		TokenHash: hash,
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, "", err
	}
	iv := inviteFromInsertRow(row)
	_ = s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      in.Email,
		Subject: "You've been invited to Qeet",
		Body:    fmt.Sprintf("Accept the invite: %s/invite/accept?token=%s", s.baseAppURL, raw),
	})
	return &iv, raw, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Invite, error) {
	rows, err := s.q.ListInvites(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rows))
	for _, row := range rows {
		out = append(out, inviteFromListRow(row))
	}
	return out, nil
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.RevokeInvite(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
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

	inv, err := s.q.WithTx(tx).GetInviteForAccept(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrBadRequest.WithDetail("invalid token")
		}
		return nil, err
	}
	if inv.Status != "pending" {
		return nil, errs.ErrBadRequest.WithDetail("invite " + inv.Status)
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = s.q.WithTx(tx).MarkInviteExpired(ctx, inv.ID)
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
	`, inv.TenantID, inv.Email, in.DisplayName).Scan(&userID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)
	`, userID, pwHash); err != nil {
		return nil, err
	}
	if roleID := pgtypeToUUIDPtr(inv.RoleID); roleID != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)
		`, userID, inv.TenantID, *roleID); err != nil {
			return nil, err
		}
	}
	if err := s.q.WithTx(tx).MarkInviteAccepted(ctx, inv.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AcceptResult{UserID: userID, TenantID: inv.TenantID}, nil
}
