// Package invite lets a tenant admin invite an email address into a
// tenant with a pre-assigned role. The invitee follows the link, creates
// their account, and the invite is consumed in the same transaction.
package invite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

// inviteFromRegenerateRow mirrors inviteFromInsertRow for the (field-identical)
// RegenerateInvite row — sqlc emits a distinct row type per query.
func inviteFromRegenerateRow(row dbgen.RegenerateInviteRow) Invite {
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
	s.sendInviteEmail(ctx, iv.ID, in.Email, raw)
	return &iv, raw, nil
}

// sendInviteEmail delivers the accept link. A failure is logged (not swallowed)
// but does not fail the request — the invite row exists and the admin can
// resend or copy the returned token. Delivery to unverified recipients fails
// while Amazon SES is in sandbox mode.
func (s *Service) sendInviteEmail(ctx context.Context, inviteID uuid.UUID, email, rawToken string) {
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "You've been invited to Qeet",
		Body:    fmt.Sprintf("Accept the invite: %s/invite/accept?token=%s", s.baseAppURL, rawToken),
	}); err != nil {
		slog.Warn("invite email send failed", "err", err, "invite_id", inviteID, "email", email)
	}
}

// Resend rotates the invite token, extends the expiry, and re-sends the email.
// Only pending/expired invites for this tenant qualify.
func (s *Service) Resend(ctx context.Context, tenantID, id uuid.UUID) (*Invite, string, error) {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	row, err := s.q.RegenerateInvite(ctx, dbgen.RegenerateInviteParams{
		ID:        id,
		TenantID:  tenantID,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", errs.ErrNotFound.WithDetail("no pending invite to resend")
		}
		return nil, "", err
	}
	iv := inviteFromRegenerateRow(row)
	s.sendInviteEmail(ctx, iv.ID, iv.Email, raw)
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

func (s *Service) Revoke(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := s.q.RevokeInvite(ctx, dbgen.RevokeInviteParams{ID: id, TenantID: tenantID})
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
		return nil, errs.ErrAuthPasswordBreached
	}
	hash := codes.Hash(in.Token)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	inv, err := qtx.GetInviteForAccept(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrInviteLinkInvalid
		}
		return nil, err
	}
	if inv.Status != "pending" {
		return nil, errs.ErrInviteInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = qtx.MarkInviteExpired(ctx, inv.ID)
		_ = tx.Commit(ctx)
		return nil, errs.ErrInviteExpired
	}

	// Email is globally unique (migration 0022). If the invited address already
	// has an account, the anonymous set-a-password path can't INSERT a new user
	// row — that used to surface as an opaque unique-violation 500. Send the
	// invitee to sign in and accept as themselves (AcceptAuthenticated).
	if _, err := qtx.FindUserIDByEmail(ctx, inv.Email); err == nil {
		return nil, errs.ErrInviteAccountExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	pwHash, err := password.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	userID, err := qtx.InsertInvitedUser(ctx, dbgen.InsertInvitedUserParams{
		TenantID:    pgtype.UUID{Bytes: inv.TenantID, Valid: true},
		Email:       inv.Email,
		DisplayName: in.DisplayName,
	})
	if err != nil {
		return nil, err
	}
	if err := qtx.InsertInviteCredential(ctx, dbgen.InsertInviteCredentialParams{
		UserID:       userID,
		PasswordHash: pwHash,
	}); err != nil {
		return nil, err
	}
	if roleID := pgtypeToUUIDPtr(inv.RoleID); roleID != nil {
		if err := qtx.GrantUserRole(ctx, dbgen.GrantUserRoleParams{
			UserID:   userID,
			TenantID: inv.TenantID,
			RoleID:   *roleID,
		}); err != nil {
			return nil, err
		}
	}
	if err := qtx.MarkInviteAccepted(ctx, inv.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AcceptResult{UserID: userID, TenantID: inv.TenantID}, nil
}

// ReceivedInvite is a pending invitation addressed to a signed-in user, with
// the inviting org's display name — the "pending invitations" inbox for a user
// who may not belong to any org yet.
type ReceivedInvite struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	TenantName string     `json:"tenant_name"`
	TenantSlug string     `json:"tenant_slug"`
	Email      string     `json:"email"`
	RoleID     *uuid.UUID `json:"role_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ListForUser returns the pending invitations addressed to the caller's email.
func (s *Service) ListForUser(ctx context.Context, userID uuid.UUID) ([]ReceivedInvite, error) {
	email, err := s.q.GetUserEmailByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized
		}
		return nil, err
	}
	rows, err := s.q.ListInvitesForEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	out := make([]ReceivedInvite, 0, len(rows))
	for _, r := range rows {
		out = append(out, ReceivedInvite{
			ID:         r.ID,
			TenantID:   r.TenantID,
			TenantName: r.TenantName,
			TenantSlug: r.TenantSlug,
			Email:      r.Email,
			RoleID:     pgtypeToUUIDPtr(r.RoleID),
			ExpiresAt:  r.ExpiresAt,
			CreatedAt:  r.CreatedAt,
		})
	}
	return out, nil
}

// DeclineForUser dismisses a pending invitation addressed to the caller's email.
func (s *Service) DeclineForUser(ctx context.Context, userID, inviteID uuid.UUID) error {
	email, err := s.q.GetUserEmailByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrUnauthorized
		}
		return err
	}
	n, err := s.q.DeclineInviteForEmail(ctx, dbgen.DeclineInviteForEmailParams{
		ID:    inviteID,
		Email: email,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrInviteInvalid
	}
	return nil
}

// pendingInvite is the minimal invite shape the authed-accept helper needs, fed
// from either the by-token or by-id lookup (sqlc emits a distinct row type per
// query, but they're field-identical so a direct conversion is legal).
type pendingInvite struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Email     string
	RoleID    pgtype.UUID
	Status    string
	ExpiresAt time.Time
}

// AcceptAuthenticated lets an already signed-in user join the invited tenant
// with their existing account (via the emailed token) — no new user row, no
// password. The path for a user who signed up first (tenant-less) and only
// then opened an invite link.
func (s *Service) AcceptAuthenticated(ctx context.Context, userID uuid.UUID, token string) (*AcceptResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	inv, err := qtx.GetInviteForAccept(ctx, codes.Hash(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrInviteLinkInvalid
		}
		return nil, err
	}
	return s.grantAuthedAccept(ctx, tx, qtx, userID, pendingInvite(inv))
}

// AcceptAuthenticatedByID is the in-app "accept from my inbox" counterpart: the
// caller picks an invite by id (from ListForUser) rather than pasting a token.
func (s *Service) AcceptAuthenticatedByID(ctx context.Context, userID, inviteID uuid.UUID) (*AcceptResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	inv, err := qtx.GetInviteByIDForAccept(ctx, inviteID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrInviteLinkInvalid
		}
		return nil, err
	}
	return s.grantAuthedAccept(ctx, tx, qtx, userID, pendingInvite(inv))
}

// grantAuthedAccept validates a pending invite against the signed-in caller and
// attaches the membership. The invite is bound to an email; only the account
// that owns that email may accept it as themselves.
func (s *Service) grantAuthedAccept(ctx context.Context, tx pgx.Tx, qtx *dbgen.Queries, userID uuid.UUID, inv pendingInvite) (*AcceptResult, error) {
	email, err := qtx.GetUserEmailByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized
		}
		return nil, err
	}
	if inv.Status != "pending" {
		return nil, errs.ErrInviteInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = qtx.MarkInviteExpired(ctx, inv.ID)
		_ = tx.Commit(ctx)
		return nil, errs.ErrInviteExpired
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(inv.Email)) {
		return nil, errs.ErrInviteEmailMismatch
	}
	if roleID := pgtypeToUUIDPtr(inv.RoleID); roleID != nil {
		if err := qtx.GrantUserRole(ctx, dbgen.GrantUserRoleParams{
			UserID:   userID,
			TenantID: inv.TenantID,
			RoleID:   *roleID,
		}); err != nil {
			return nil, err
		}
	}
	if err := qtx.MarkInviteAccepted(ctx, inv.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AcceptResult{UserID: userID, TenantID: inv.TenantID}, nil
}
