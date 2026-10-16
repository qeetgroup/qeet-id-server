package invite

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invitations/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An invited person without an account may accept with a passkey instead of a
// password. The ceremony is the passkey service's (POST
// /invites/accept/passkey/begin and /finish); this side tells it which
// invitation a link names and accepts it for the account the ceremony creates.
// The acceptance screen first looks the invitation up to learn which ways of
// accepting the organisation allows.

// AcceptMethods reports which ways of signing in an organisation allows.
// Satisfied by *authpolicy.Service; an interface so this package does not
// import it. Wired in internal/bootstrap/dependencies.go.
type AcceptMethods interface {
	AllowedSignInMethods(ctx context.Context, tenantID uuid.UUID) (password, passkey, magicLink bool, err error)
}

// SetAcceptMethods wires the organisation's sign-in methods into Lookup (nil:
// every invitation offers a password only).
func (s *Service) SetAcceptMethods(m AcceptMethods) { s.methods = m }

// InvitationForNewAccount returns the id, organisation and email of the
// invitation token names when a new account may accept it now; otherwise the
// refusal Accept gives. An invitation found expired is marked so.
func (s *Service) InvitationForNewAccount(ctx context.Context, token string) (uuid.UUID, uuid.UUID, string, error) {
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
		return uuid.Nil, uuid.Nil, "", errs.ErrInviteInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		_ = qtx.MarkInviteExpired(ctx, inv.ID)
		_ = tx.Commit(ctx)
		return uuid.Nil, uuid.Nil, "", errs.ErrInviteExpired
	}
	if _, err := qtx.FindUserIDByEmail(ctx, inv.Email); err == nil {
		return uuid.Nil, uuid.Nil, "", errs.ErrInviteAccountExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, "", err
	}
	return inv.ID, inv.TenantID, inv.Email, nil
}

// AcceptForNewAccountTx accepts invitation id for userID, the account just
// created in tx for email in tenantID. The invitation is read under lock and
// must still be pending, unexpired, and for that email and organisation; then
// the invited role is granted, the account marked as owning its address, and
// the invitation marked accepted. Any refusal undoes the caller's transaction.
func (s *Service) AcceptForNewAccountTx(ctx context.Context, tx pgx.Tx, id, tenantID, userID uuid.UUID, email string) error {
	qtx := s.q.WithTx(tx)
	inv, err := qtx.GetInviteByIDForAccept(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrInviteInvalid
	}
	if err != nil {
		return err
	}
	if inv.Status != "pending" || inv.TenantID != tenantID ||
		!strings.EqualFold(strings.TrimSpace(inv.Email), strings.TrimSpace(email)) {
		return errs.ErrInviteInvalid
	}
	if time.Now().After(inv.ExpiresAt) {
		return errs.ErrInviteExpired
	}
	if roleID := pgtypeToUUIDPtr(inv.RoleID); roleID != nil {
		if err := qtx.GrantUserRole(ctx, dbgen.GrantUserRoleParams{
			UserID:   userID,
			TenantID: inv.TenantID,
			RoleID:   *roleID,
		}); err != nil {
			return err
		}
	}
	if err := qtx.MarkInvitedAccountVerified(ctx, userID); err != nil {
		return err
	}
	return qtx.MarkInviteAccepted(ctx, inv.ID)
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
	// AccountExists: an account already holds the address, so the invitee
	// signs in and accepts as themselves instead.
	AccountExists bool `json:"account_exists"`
	// Methods are the ways a new account may accept: a password, a passkey.
	Methods struct {
		Password bool `json:"password"`
		Passkey  bool `json:"passkey"`
	} `json:"methods"`
}

// Lookup previews the invitation token names, refused as Accept would refuse
// it when it is not pending or has expired. A password is always offered,
// whatever the organisation's methods, as Accept has always allowed; a
// passkey only where the organisation allows passkeys.
func (s *Service) Lookup(ctx context.Context, token string) (*InvitationPreview, error) {
	row, err := s.q.LookupInvite(ctx, codes.Hash(token))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrInviteLinkInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.Status != "pending" {
		return nil, errs.ErrInviteInvalid
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errs.ErrInviteExpired
	}
	out := &InvitationPreview{Email: row.Email, ExpiresAt: row.ExpiresAt, AccountExists: row.AccountExists}
	out.Organization.Name, out.Organization.Slug = row.TenantName, row.TenantSlug
	out.Methods.Password = true
	if s.methods != nil {
		_, passkey, _, err := s.methods.AllowedSignInMethods(ctx, row.TenantID)
		if err != nil {
			return nil, err
		}
		out.Methods.Passkey = passkey
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
