package invite

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An invited person without an account may accept with a passkey instead of a
// password. The passkey service runs the ceremony (POST
// /invites/accept/passkey/begin and /finish); this file finds the invitation a
// link names and accepts it for the account the ceremony creates.

// SetAcceptMethods sets the source of each organization's sign-in methods, used
// by Accept and Lookup. Without it every invitation offers a password only.
func (s *Service) SetAcceptMethods(m authpolicy.SignInMethodsChecker) { s.methods = m }

// acceptMethods reports whether a new account may accept an invitation to
// organizationID with a password, and with a passkey.
func (s *Service) acceptMethods(ctx context.Context, organizationID uuid.UUID) (passwordOn, passkeyOn bool, err error) {
	if s.methods == nil {
		return true, false, nil
	}
	passwordOn, passkeyOn, _, err = s.methods.AllowedSignInMethods(ctx, organizationID)
	return passwordOn, passkeyOn, err
}

// InvitationForNewAccount returns the id, organization and email of the
// invitation token names when a new account may accept it now; otherwise the
// refusal Accept gives. An invitation found expired is marked so.
func (s *Service) InvitationForNewAccount(ctx context.Context, token string) (uuid.UUID, uuid.UUID, string, error) {
	id, organizationID, email, err := s.pendingForNewAccount(ctx, token)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	if err := s.CheckInvitationSender(ctx, id); err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	// On a domain another organization manages, only that organization
	// creates the account, however the invitation came.
	if err := domainverify.CheckNewAccount(ctx, s.pool, organizationID, email); err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	return id, organizationID, email, nil
}

// pendingForNewAccount is InvitationForNewAccount before the domain check.
func (s *Service) pendingForNewAccount(ctx context.Context, token string) (uuid.UUID, uuid.UUID, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	inv, err := qtx.GetInviteForAccept(ctx, codes.Hash(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, "", errs.ErrInviteLinkInvalid
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	if inv.Status != "pending" {
		return uuid.Nil, uuid.Nil, "", ErrInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = qtx.MarkInviteExpired(ctx, inv.ID)
		_ = tx.Commit(ctx)
		return uuid.Nil, uuid.Nil, "", ErrExpired
	}
	if _, err := qtx.FindUserIDByEmail(ctx, inv.Email); err == nil {
		return uuid.Nil, uuid.Nil, "", errs.ErrInviteAccountExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, "", err
	}
	return inv.ID, inv.OrganizationID, inv.Email, nil
}

// AcceptForNewAccountTx accepts invitation id for userID, the account just
// created in tx for email in organizationID. The invitation, read under lock, must be
// pending, unexpired and for that email and organization; then the invited role is
// granted, the account activated and the acceptance recorded from ip and ua.
func (s *Service) AcceptForNewAccountTx(ctx context.Context, tx pgx.Tx, id, organizationID, userID uuid.UUID, email, ip, ua string) error {
	qtx := s.q.WithTx(tx)
	inv, err := qtx.GetInviteByIDForAccept(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return err
	}
	if inv.Status != "pending" || inv.OrganizationID != organizationID ||
		!strings.EqualFold(strings.TrimSpace(inv.Email), strings.TrimSpace(email)) {
		return ErrInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		return ErrExpired
	}
	if roleID := inv.RoleID; roleID != nil {
		if err := qtx.GrantUserRole(ctx, dbgen.GrantUserRoleParams{
			UserID:         userID,
			OrganizationID: inv.OrganizationID,
			RoleID:         *roleID,
		}); err != nil {
			return err
		}
	}
	if err := qtx.ActivateInvitedAccount(ctx, userID); err != nil {
		return err
	}
	if err := qtx.MarkInviteAccepted(ctx, inv.ID); err != nil {
		return err
	}
	return recordAccepted(ctx, tx, audit.Actor{IP: ip, UserAgent: ua}, userID, pendingInvite(inv), "passkey")
}

// InvitationPreview is what the acceptance screen shows before the invitee
// chooses how to accept.
type InvitationPreview struct {
	Organization struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"organization"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
	// AccountExists reports whether an account already holds the address; if so
	// the invitee signs in and accepts as themselves.
	AccountExists bool `json:"account_exists"`
	// Methods are the ways a new account may accept: a password, a passkey.
	Methods struct {
		Password bool `json:"password"`
		Passkey  bool `json:"passkey"`
	} `json:"methods"`
}

// Lookup previews the invitation token names, refusing it as Accept would when
// it isn't pending or has expired. Methods are the ways the organization lets
// a new account accept it, as Accept and the passkey ceremony decide.
func (s *Service) Lookup(ctx context.Context, token string) (*InvitationPreview, error) {
	row, err := s.q.LookupInvite(ctx, codes.Hash(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrInviteLinkInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.Status != "pending" {
		return nil, ErrInvalid
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrExpired
	}
	sent, err := s.q.InviteSenderByToken(ctx, codes.Hash(token))
	if err := s.checkSender(ctx, sentInvite(sent), err); err != nil {
		return nil, err
	}
	out := &InvitationPreview{Email: row.Email, ExpiresAt: row.ExpiresAt, AccountExists: row.AccountExists}
	out.Organization.Name, out.Organization.Slug = row.OrganizationName, row.OrganizationSlug
	if out.Methods.Password, out.Methods.Passkey, err = s.acceptMethods(ctx, row.OrganizationID); err != nil {
		return nil, err
	}
	return out, nil
}

type lookupInput struct {
	Token string `json:"token" validate:"required"`
}

// lookup previews an invitation for the acceptance screen. The token travels
// in the body, not the URL, so it stays out of logs.
func (h *Handler) lookup(w http.ResponseWriter, r *http.Request) {
	var in lookupInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	out, err := h.Service.Lookup(r.Context(), in.Token)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
