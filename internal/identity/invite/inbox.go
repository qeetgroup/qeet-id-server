package invite

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ReceivedInvite is a pending invitation addressed to a signed-in user, with
// the inviting org's display name — the "pending invitations" inbox for a user
// who may not belong to any org yet.
type ReceivedInvite struct {
	ID               uuid.UUID  `json:"id"`
	OrganizationID   uuid.UUID  `json:"organization_id"`
	OrganizationName string     `json:"organization_name"`
	OrganizationSlug string     `json:"organization_slug"`
	Email            string     `json:"email"`
	RoleID           *uuid.UUID `json:"role_id"`
	ExpiresAt        time.Time  `json:"expires_at"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ListForUser returns the pending invitations addressed to the caller's email.
func (s *Service) ListForUser(ctx context.Context, userID uuid.UUID) ([]ReceivedInvite, error) {
	email, err := inboxEmail(ctx, s.q, userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListInvitesForEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	out := make([]ReceivedInvite, 0, len(rows))
	for _, r := range rows {
		out = append(out, ReceivedInvite{
			ID:               r.ID,
			OrganizationID:   r.OrganizationID,
			OrganizationName: r.OrganizationName,
			OrganizationSlug: r.OrganizationSlug,
			Email:            r.Email,
			RoleID:           r.RoleID,
			ExpiresAt:        r.ExpiresAt,
			CreatedAt:        r.CreatedAt,
		})
	}
	return out, nil
}

// DeclineForUser dismisses a pending invitation addressed to the caller's
// email, recorded as theirs with actor's request details.
func (s *Service) DeclineForUser(ctx context.Context, userID, inviteID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	email, err := inboxEmail(ctx, qtx, userID)
	if err != nil {
		return err
	}
	row, err := qtx.DeclineInviteForEmail(ctx, dbgen.DeclineInviteForEmailParams{
		ID:    inviteID,
		Email: email,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, asInvitee(actor, userID).Event(row.OrganizationID, "invite.declined", "invite", inviteID,
		inviteMetadata(email, row.RoleID))); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// inboxEmail returns the caller's address for the in-app invitations inbox, or
// ErrInviteEmailNotVerified until they have proven it. The emailed invitation
// link needs no such check: having the link is the proof.
func inboxEmail(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) (string, error) {
	row, err := q.GetInboxEmail(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errs.ErrUnauthorized
		}
		return "", err
	}
	if !row.Verified {
		return "", errs.ErrInviteEmailNotVerified
	}
	return row.Email, nil
}
