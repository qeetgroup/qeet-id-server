// Package invite lets an organization admin invite an email address into an organization with
// a pre-assigned role. The invitee accepts by link, either creating an account
// or, when signed in, joining with their existing one.
package invite

import (
	"cmp"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Invite is an invitation, without its token.
type Invite struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Email          string     `json:"email"`
	RoleID         *uuid.UUID `json:"role_id"`
	Status         string     `json:"status"`
	ExpiresAt      time.Time  `json:"expires_at"`
	AcceptedAt     *time.Time `json:"accepted_at"`
	CreatedAt      time.Time  `json:"created_at"`
	// Delivery is set on the invitation Create or Resend returns: whether its
	// email went out.
	Delivery *Delivery `json:"delivery,omitempty"`
}

// Delivery is what happened to an invitation's email: "sent" when a provider
// accepted it, or "not_sent" with the reason (the address is suppressed after
// a bounce or complaint, no provider is configured, or the provider refused
// it). The invitation exists either way, and its link can be shared by hand.
type Delivery struct {
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func deliveryOf(err error) *Delivery {
	if err == nil {
		return &Delivery{Status: "sent"}
	}
	d := &Delivery{Status: "not_sent", Code: "email.send_failed", Message: "The email could not be sent."}
	var e *errs.Error
	if errors.As(err, &e) {
		d.Code, d.Message = e.Code, e.Message
	}
	return d
}

// CreateInput is what Create takes.
type CreateInput struct {
	OrganizationID uuid.UUID  `json:"organization_id" validate:"required"`
	Email          string     `json:"email" validate:"required,email"`
	RoleID         *uuid.UUID `json:"role_id"`
}

// Service manages invitations.
type Service struct {
	*Seats
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	sender     notifier.Sender
	ttl        time.Duration
	baseAppURL string
	rules      authpolicy.PasswordRules
	methods    authpolicy.SignInMethodsChecker
	grants     func(ctx context.Context, caller *httpx.Principal, organizationID, roleID uuid.UUID) error
}

// Deps are what the invitation service is built from. Every field is
// required but TTL.
type Deps struct {
	Sender     notifier.Sender
	TTL        time.Duration // how long an invitation stays good (zero: 14 days)
	BaseAppURL string        // where an invitation's link points
	// Rules is the password check Accept runs; Methods the sign-in methods an
	// organization allows, which decide how an invitation may be accepted.
	Rules   authpolicy.PasswordRules
	Methods authpolicy.SignInMethodsChecker
	Limits  entitlements.PlanLimiter // the plan's seats
	// Grants checks that whoever sent an invitation may still give its role
	// when it is accepted (rbac.Repository.CheckGrantRole).
	Grants func(ctx context.Context, caller *httpx.Principal, organizationID, roleID uuid.UUID) error
}

// NewService returns the invitation service built from d.
func NewService(pool *pgxpool.Pool, d Deps) (*Service, error) {
	switch {
	case d.Sender == nil:
		return nil, errors.New("invite: the invitation service needs a sender")
	case d.Rules == nil:
		return nil, errors.New("invite: the invitation service needs password rules")
	case d.Methods == nil:
		return nil, errors.New("invite: the invitation service needs sign-in methods")
	case d.Grants == nil:
		return nil, errors.New("invite: the invitation service needs a grant check")
	}
	seats, err := NewSeats(pool, d.Limits)
	if err != nil {
		return nil, err
	}
	return &Service{Seats: seats, pool: pool, q: dbgen.New(pool), sender: d.Sender, ttl: cmp.Or(d.TTL, 14*24*time.Hour),
		baseAppURL: d.BaseAppURL, rules: d.Rules, methods: d.Methods, grants: d.Grants}, nil
}

func inviteFromInsertRow(row dbgen.InsertInviteRow) Invite {
	return Invite{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Email:          row.Email,
		RoleID:         row.RoleID,
		Status:         row.Status,
		ExpiresAt:      row.ExpiresAt,
		AcceptedAt:     row.AcceptedAt,
		CreatedAt:      row.CreatedAt,
	}
}

// inviteFromRegenerateRow mirrors inviteFromInsertRow for the (field-identical)
// RegenerateInvite row — sqlc emits a distinct row type per query.
func inviteFromRegenerateRow(row dbgen.RegenerateInviteRow) Invite {
	return Invite{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Email:          row.Email,
		RoleID:         row.RoleID,
		Status:         row.Status,
		ExpiresAt:      row.ExpiresAt,
		AcceptedAt:     row.AcceptedAt,
		CreatedAt:      row.CreatedAt,
	}
}

func inviteFromListRow(row dbgen.ListInvitesRow) Invite {
	return Invite{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Email:          row.Email,
		RoleID:         row.RoleID,
		Status:         row.Status,
		ExpiresAt:      row.ExpiresAt,
		AcceptedAt:     row.AcceptedAt,
		CreatedAt:      row.CreatedAt,
	}
}

// errRoleNotFound refuses an invitation whose role isn't the organization's. A missing
// and another organization's role get the same answer, as on the rbac role routes.
var errRoleNotFound = errs.ErrNotFound.WithDetail("role not found")

// inviteMetadata is the audit metadata of an invitation to email with roleID.
// It never carries the invitation's token.
func inviteMetadata(email string, roleID *uuid.UUID) map[string]any {
	return map[string]any{"email": email, "role_id": roleID}
}

// Create stores an invitation from actor, recorded as theirs, and emails its
// link. A role it carries must be the organization's, or it is errRoleNotFound; one
// carrying none, to someone at home in another organization, would join them
// to nothing and is ErrInviteRoleRequired. The address is kept lower-case.
func (s *Service) Create(ctx context.Context, in CreateInput, actor audit.Actor) (*Invite, string, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.RoleID == nil {
		elsewhere, err := s.q.AccountHomeElsewhere(ctx, dbgen.AccountHomeElsewhereParams{Email: in.Email, OrganizationID: in.OrganizationID})
		if err != nil {
			return nil, "", err
		}
		if elsewhere {
			return nil, "", ErrRoleRequired
		}
	}
	// Plan gate: a new invite consumes a seat, so refuse once the organization's seat
	// limit (members + pending invites) is reached.
	lim, err := s.SeatLimit(ctx, in.OrganizationID)
	if err != nil {
		return nil, "", err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().UTC().Add(s.ttl)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	if lim >= 0 {
		if err := s.q.WithTx(tx).LockSeats(ctx, in.OrganizationID); err != nil {
			return nil, "", err
		}
		n, err := s.q.WithTx(tx).CountSeats(ctx, in.OrganizationID)
		if err != nil {
			return nil, "", err
		}
		if int(n) >= lim {
			return nil, "", seatLimitReached(lim)
		}
	}
	row, err := s.q.WithTx(tx).InsertInvite(ctx, dbgen.InsertInviteParams{
		OrganizationID: in.OrganizationID,
		Email:          in.Email,
		RoleID:         in.RoleID,
		InvitedBy:      actor.UserID,
		TokenHash:      hash,
		ExpiresAt:      expires,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", errRoleNotFound
	}
	if err != nil {
		return nil, "", err
	}
	iv := inviteFromInsertRow(row)
	if err := audit.Record(ctx, tx, actor.Event(iv.OrganizationID, "invite.created", "invite", iv.ID, inviteMetadata(iv.Email, iv.RoleID))); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	iv.Delivery = deliveryOf(s.sendInviteEmail(ctx, in.OrganizationID, iv.ID, in.Email, raw))
	return &iv, raw, nil
}

// RoleOf returns the role one of the organization's invitations grants (nil: none),
// or ErrNotFound.
func (s *Service) RoleOf(ctx context.Context, organizationID, id uuid.UUID) (*uuid.UUID, error) {
	role, err := s.q.GetInviteRole(ctx, dbgen.GetInviteRoleParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return role, nil
}

// Resend rotates the invite token, extends the expiry, and re-sends the email,
// recorded as actor's. Only pending/expired invites for this organization qualify.
func (s *Service) Resend(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) (*Invite, string, error) {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).RegenerateInvite(ctx, dbgen.RegenerateInviteParams{
		ID:             id,
		OrganizationID: organizationID,
		TokenHash:      hash,
		ExpiresAt:      time.Now().UTC().Add(s.ttl),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", errs.ErrNotFound.WithDetail("no pending invite to resend")
		}
		return nil, "", err
	}
	iv := inviteFromRegenerateRow(row)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "invite.resent", "invite", iv.ID, inviteMetadata(iv.Email, iv.RoleID))); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	iv.Delivery = deliveryOf(s.sendInviteEmail(ctx, organizationID, iv.ID, iv.Email, raw))
	return &iv, raw, nil
}

// List returns the organization's invitations.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Invite, error) {
	rows, err := s.q.ListInvites(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rows))
	for _, row := range rows {
		out = append(out, inviteFromListRow(row))
	}
	return out, nil
}

// Revoke withdraws one of the organization's pending invitations, recorded as
// actor's.
func (s *Service) Revoke(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).RevokeInvite(ctx, dbgen.RevokeInviteParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "invite.revoked", "invite", id,
		inviteMetadata(row.Email, row.RoleID))); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
