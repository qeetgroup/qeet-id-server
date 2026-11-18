package invite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// sentInvite is who sent an invitation and what it gives, read before an
// acceptance's transaction: the grant check reads the pool.
type sentInvite dbgen.InviteSenderByTokenRow

// checkSender refuses, with ErrInviteInvalid, accepting the invitation sent (read with err) when its
// sender may no longer give it: their account isn't active, they left its organization, or they
// couldn't give its role now. One no person sent, or not pending, is left to the acceptance itself.
func (s *Service) checkSender(ctx context.Context, sent sentInvite, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if sent.InvitedBy == nil || sent.Status != "pending" || time.Now().After(sent.ExpiresAt) {
		return nil
	}
	inviter := *sent.InvitedBy
	active, err := s.q.InviterActive(ctx, dbgen.InviterActiveParams{UserID: inviter, OrganizationID: sent.OrganizationID})
	if err != nil {
		return err
	}
	if !active {
		return ErrInvalid
	}
	if sent.RoleID == nil {
		return nil
	}
	organizationID := sent.OrganizationID
	caller := &httpx.Principal{UserID: &inviter, OrganizationID: &organizationID, ActorType: "user"}
	switch err := s.grants(ctx, caller, organizationID, postgres.ZeroIfNull(sent.RoleID)); {
	case errors.Is(err, errs.ErrRBACOwnerOnly), errors.Is(err, errs.ErrRBACGrantExceedsCaller):
		return ErrInvalid
	default:
		return err
	}
}

// CheckInvitationSender is checkSender for invitation id, for an acceptance
// made in a transaction of its own (the passkey ceremony's), before it opens.
func (s *Service) CheckInvitationSender(ctx context.Context, id uuid.UUID) error {
	sent, err := s.q.InviteSenderByID(ctx, id)
	return s.checkSender(ctx, sentInvite(sent), err)
}

// sendInviteEmail emails the accept link. A failure is logged and returned, for
// Invite.Delivery, but doesn't fail the request: the invite exists and the admin
// can resend it or share the link.
func (s *Service) sendInviteEmail(ctx context.Context, organizationID, inviteID uuid.UUID, email, rawToken string) error {
	inviteURL := fmt.Sprintf("%s/invite/accept?token=%s", s.baseAppURL, rawToken)
	if err := s.sender.Send(ctx, notifier.Message{
		TemplateKey:       "invite",
		TemplateVariables: map[string]string{"invite_url": inviteURL},
		OrganizationID:    organizationID.String(),
		Channel:           "email",
		To:                email,
		Subject:           "You've been invited to Qeet",
		Body:              fmt.Sprintf("Accept your invitation: %s", inviteURL),
		HTML: emailtmpl.Action(
			"You've been invited to Qeet",
			"You've been invited to join an organization on Qeet ID. Click the button below to accept.",
			"Accept invitation", inviteURL,
			"If you weren't expecting this invitation, you can safely ignore this email.",
		),
	}); err != nil {
		slog.Warn("invite email send failed", "err", err, "invite_id", inviteID)
		return err
	}
	return nil
}
