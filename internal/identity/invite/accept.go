package invite

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// asInvitee returns actor, the request's details, as the invitee userID.
func asInvitee(actor audit.Actor, userID uuid.UUID) audit.Actor {
	actor.UserID, actor.Type = &userID, "user"
	return actor
}

// recordAccepted records, in tx, that userID accepted inv by method.
func recordAccepted(ctx context.Context, tx pgx.Tx, actor audit.Actor, userID uuid.UUID, inv pendingInvite, method string) error {
	meta := inviteMetadata(inv.Email, inv.RoleID)
	meta["method"] = method
	return audit.Record(ctx, tx, asInvitee(actor, userID).Event(inv.OrganizationID, "invite.accepted", "invite", inv.ID, meta))
}

// AcceptInput is what Accept takes.
type AcceptInput struct {
	Token       string `json:"token" validate:"required"`
	Password    string `json:"password" validate:"required,max=256"`
	DisplayName string `json:"display_name" validate:"omitempty,max=200"`
}

// AcceptResult is the account an accepted invitation created.
type AcceptResult struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
}

// Accept creates the invitee's password account from an invitation's token,
// under the inviting organization's sign-in rules. The acceptance is recorded
// as the new account's, with actor's request details.
func (s *Service) Accept(ctx context.Context, in AcceptInput, actor audit.Actor) (*AcceptResult, error) {
	// The new account will belong to the inviting organization, so its
	// methods and rules apply: no password account where passwords can't sign
	// in. Checked once the invite is known to be good and before the
	// transaction, as they read the policy and may call the breach service.
	_, organizationID, email, err := s.InvitationForNewAccount(ctx, in.Token)
	if err != nil {
		return nil, err
	}
	passwordOn, _, err := s.acceptMethods(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if !passwordOn {
		return nil, errs.ErrAuthMethodDisabled
	}
	if err := s.rules.ValidateForOrganization(ctx, organizationID, email, in.Password); err != nil {
		return nil, err
	}
	pwHash, err := password.Hash(in.Password)
	if err != nil {
		return nil, err
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
		return nil, ErrInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = qtx.MarkInviteExpired(ctx, inv.ID)
		_ = tx.Commit(ctx)
		return nil, ErrExpired
	}

	// Email is globally unique (migration 0022), so an address that already has
	// an account can't get a new one here: the invitee signs in and accepts as
	// themselves (AcceptAuthenticated).
	if _, err := qtx.FindUserIDByEmail(ctx, inv.Email); err == nil {
		return nil, errs.ErrInviteAccountExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	userID, err := qtx.InsertInvitedUser(ctx, dbgen.InsertInvitedUserParams{
		OrganizationID: &inv.OrganizationID,
		Email:          inv.Email,
		DisplayName:    in.DisplayName,
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
	if roleID := inv.RoleID; roleID != nil {
		if err := qtx.GrantUserRole(ctx, dbgen.GrantUserRoleParams{
			UserID:         userID,
			OrganizationID: inv.OrganizationID,
			RoleID:         *roleID,
		}); err != nil {
			return nil, err
		}
	}
	if err := qtx.MarkInviteAccepted(ctx, inv.ID); err != nil {
		return nil, err
	}
	if err := recordAccepted(ctx, tx, actor, userID, pendingInvite(inv), "password"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AcceptResult{UserID: userID, OrganizationID: inv.OrganizationID}, nil
}

// pendingInvite is the minimal invite shape the authed-accept helper needs, fed
// from either the by-token or by-id lookup (sqlc emits a distinct row type per
// query, but they're field-identical so a direct conversion is legal).
type pendingInvite struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Email          string
	RoleID         *uuid.UUID
	Status         string
	ExpiresAt      time.Time
}

// AcceptAuthenticated lets a signed-in user join the invited organization with their
// existing account, using the emailed token: no new user and no password. It
// is recorded as theirs, with actor's request details.
func (s *Service) AcceptAuthenticated(ctx context.Context, userID uuid.UUID, token string, actor audit.Actor) (*AcceptResult, error) {
	sent, err := s.q.InviteSenderByToken(ctx, codes.Hash(token))
	if err := s.checkSender(ctx, sentInvite(sent), err); err != nil {
		return nil, err
	}
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
	return s.grantAuthedAccept(ctx, tx, qtx, userID, pendingInvite(inv), actor)
}

// AcceptAuthenticatedByID is the in-app "accept from my inbox" counterpart: the
// caller picks an invite by id (from ListForUser) rather than pasting a token.
func (s *Service) AcceptAuthenticatedByID(ctx context.Context, userID, inviteID uuid.UUID, actor audit.Actor) (*AcceptResult, error) {
	// The inbox is closed until the address is proved, whoever sent the invitation.
	if _, err := inboxEmail(ctx, s.q, userID); err != nil {
		return nil, err
	}
	if err := s.CheckInvitationSender(ctx, inviteID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	if _, err := inboxEmail(ctx, qtx, userID); err != nil {
		return nil, err
	}
	inv, err := qtx.GetInviteByIDForAccept(ctx, inviteID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrInviteLinkInvalid
		}
		return nil, err
	}
	return s.grantAuthedAccept(ctx, tx, qtx, userID, pendingInvite(inv), actor)
}

// grantAuthedAccept validates a pending invite against the signed-in caller and
// attaches the membership. The invite is bound to an email; only the account
// that owns that email may accept it as themselves.
func (s *Service) grantAuthedAccept(ctx context.Context, tx pgx.Tx, qtx *dbgen.Queries, userID uuid.UUID, inv pendingInvite, actor audit.Actor) (*AcceptResult, error) {
	email, err := qtx.GetUserEmailByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrUnauthorized
		}
		return nil, err
	}
	if inv.Status != "pending" {
		return nil, ErrInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = qtx.MarkInviteExpired(ctx, inv.ID)
		_ = tx.Commit(ctx)
		return nil, ErrExpired
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(inv.Email)) {
		return nil, ErrEmailMismatch
	}
	// With no role, the invitation joins only someone whose home it is.
	if inv.RoleID == nil {
		home, err := qtx.IsHomeOrganization(ctx, dbgen.IsHomeOrganizationParams{UserID: userID, OrganizationID: inv.OrganizationID})
		if err != nil {
			return nil, err
		}
		if !home {
			return nil, ErrRoleRequired
		}
	}
	if roleID := inv.RoleID; roleID != nil {
		if err := qtx.GrantUserRole(ctx, dbgen.GrantUserRoleParams{
			UserID:         userID,
			OrganizationID: inv.OrganizationID,
			RoleID:         *roleID,
		}); err != nil {
			return nil, err
		}
	}
	if err := qtx.MarkInviteAccepted(ctx, inv.ID); err != nil {
		return nil, err
	}
	if err := recordAccepted(ctx, tx, actor, userID, inv, "existing_account"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AcceptResult{UserID: userID, OrganizationID: inv.OrganizationID}, nil
}
