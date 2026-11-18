package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Accepting an invitation with a passkey: an invited person without an account
// founds one on a passkey. The ceremony takes its email and organization from
// the invitation; finishing it creates the account, stores the passkey and
// accepts the invitation in one transaction. A failed one leaves it pending.

// InvitationAcceptor is the slice of the invitation service this needs. It is
// satisfied by identity/invite.Service without this package importing it.
type InvitationAcceptor interface {
	// InvitationForNewAccount returns the id, organization and email of the
	// invitation token names if a new account may accept it now, or the password
	// path's refusal (invalid link, not pending, expired, or the email is taken).
	InvitationForNewAccount(ctx context.Context, token string) (id, organizationID uuid.UUID, email string, err error)
	// AcceptForNewAccountTx accepts invitation id for userID, the account just created in tx for email in
	// organizationID: the invitation, read under lock, must still be pending, unexpired and for that
	// email and organization. It grants the role and records the acceptance, from ip with user agent ua.
	AcceptForNewAccountTx(ctx context.Context, tx pgx.Tx, id, organizationID, userID uuid.UUID, email, ip, ua string) error
	// CheckInvitationSender refuses invitation id once whoever sent it may no
	// longer give it. It reads the pool, so it runs before the transaction.
	CheckInvitationSender(ctx context.Context, id uuid.UUID) error
}

// BeginInviteSignup starts the ceremony for the invitation token names. It is
// refused as the password path would be, or when the organization has passkeys
// off. Starting again replaces an earlier ceremony for the same invitation.
func (s *Service) BeginInviteSignup(ctx context.Context, token, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	inviteID, organizationID, email, err := s.invitations.InvitationForNewAccount(ctx, token)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if err := s.passkeysAllowed(ctx, organizationID); err != nil {
		return uuid.Nil, nil, err
	}
	if err := s.q.DeleteInviteWebAuthnSessions(ctx, &inviteID); err != nil {
		return uuid.Nil, nil, err
	}
	return s.beginSignupFor(ctx, organizationID, inviteID, email, displayName)
}

// FinishInviteSignup verifies the passkey, creates the account in the inviting
// organization with it, accepts the invitation, and signs the person in. The
// passkey is named as in FinishRegister.
func (s *Service) FinishInviteSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (*auth.TokenPair, error) {
	name, err := enrolmentName(name, ua)
	if err != nil {
		return nil, err
	}
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return nil, err
	}
	if sess.inviteID == uuid.Nil || sess.organizationID == uuid.Nil {
		return nil, ErrSessionInvalid
	}
	// The organization may have switched passkeys off since the ceremony began,
	// or whoever sent the invitation lost the right to.
	if err := s.passkeysAllowed(ctx, sess.organizationID); err != nil {
		return nil, err
	}
	if err := s.invitations.CheckInvitationSender(ctx, sess.inviteID); err != nil {
		return nil, err
	}
	userID, err := s.createUserFromSignup(ctx, sess, cred, name, func(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
		return s.invitations.AcceptForNewAccountTx(ctx, tx, sess.inviteID, sess.organizationID, userID, sess.email, ip, ua)
	})
	if errors.Is(err, errs.ErrAuthEmailExists) {
		// An account took the address after the ceremony began.
		return nil, errs.ErrInviteAccountExists
	}
	if err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, userID, sess.organizationID, ip, ua, "invite_accept")
}

type inviteSignupBeginInput struct {
	Token       string `json:"token"`
	DisplayName string `json:"display_name"`
}

// inviteSignupBegin starts accepting an invitation with a passkey — the
// passkey counterpart to POST /invites/accept.
func (h *Handler) inviteSignupBegin(w http.ResponseWriter, r *http.Request) {
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in inviteSignupBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Token == "" {
		httpx.WriteError(w, r, errs.ErrInviteLinkInvalid)
		return
	}
	if len(in.DisplayName) > 200 {
		httpx.WriteError(w, r, errs.ErrValidationFailed.WithFields([]errs.FieldError{
			{Field: "display_name", Code: "max", Message: "Use at most 200 characters."},
		}))
		return
	}
	sessionID, options, err := h.Service.BeginInviteSignup(r.Context(), in.Token, in.DisplayName)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

// inviteSignupFinish completes it and returns the new session's token pair, as
// POST /invites/accept does.
func (h *Handler) inviteSignupFinish(w http.ResponseWriter, r *http.Request) {
	var in signupFinishInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.FinishInviteSignup(r.Context(), in.SessionID, in.Credential, in.Name, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
