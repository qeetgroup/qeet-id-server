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
	"github.com/jackc/pgx/v5/pgtype"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Accepting an invitation with a passkey. An invited person without an account
// founds one on a passkey instead of a password: the ceremony is a passkey
// sign-up whose email and organisation are copied from the invitation when it
// begins, and which, when it finishes, creates the account, stores the passkey
// and accepts the invitation (the invited role, the invitation marked
// accepted) in one transaction, then signs the person in as the password path
// does. A ceremony that fails, expires or is abandoned leaves the invitation
// pending; each ceremony can be finished once.

// InvitationAcceptor is the slice of the invitation service this needs.
// Satisfied by identity/invitations.Service; an interface so this package does
// not import it. Wired in internal/bootstrap/dependencies.go.
type InvitationAcceptor interface {
	// InvitationForNewAccount returns the id, organisation and email of the
	// invitation token names when a new account may accept it now, and
	// otherwise the refusal the password path gives: the link is invalid,
	// the invitation is no longer pending or has expired, or an account
	// already holds the email.
	InvitationForNewAccount(ctx context.Context, token string) (id, tenantID uuid.UUID, email string, err error)
	// AcceptForNewAccountTx accepts invitation id for userID, the account
	// just created in tx for email in tenantID: the invitation, read under
	// lock, must still be pending, unexpired and for that email and
	// organisation. It grants the invited role and marks it accepted.
	AcceptForNewAccountTx(ctx context.Context, tx pgx.Tx, id, tenantID, userID uuid.UUID, email string) error
}

// SetInvitations wires invitation acceptance by passkey (nil turns it off).
func (s *Service) SetInvitations(a InvitationAcceptor) { s.invitations = a }

// BeginInviteSignup starts the ceremony for the invitation token names. It is
// refused as the password path would refuse the invitation, and when the
// inviting organisation has passkeys switched off. Starting again replaces an
// earlier ceremony for the same invitation, so an abandoned one never blocks
// it.
func (s *Service) BeginInviteSignup(ctx context.Context, token, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	if s.invitations == nil {
		return uuid.Nil, nil, errs.ErrNotImplemented
	}
	inviteID, tenantID, email, err := s.invitations.InvitationForNewAccount(ctx, token)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if err := s.passkeysAllowed(ctx, tenantID); err != nil {
		return uuid.Nil, nil, err
	}
	if err := s.q.DeleteInviteWebAuthnSessions(ctx, pgtype.UUID{Bytes: inviteID, Valid: true}); err != nil {
		return uuid.Nil, nil, err
	}
	return s.beginSignupFor(ctx, tenantID, inviteID, email, displayName)
}

// FinishInviteSignup verifies the passkey, creates the account in the inviting
// organisation with it, accepts the invitation, and signs the person in. The
// passkey is named as in FinishRegister.
func (s *Service) FinishInviteSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (*auth.TokenPair, error) {
	if s.invitations == nil {
		return nil, errs.ErrNotImplemented
	}
	name, err := enrolmentName(name, ua)
	if err != nil {
		return nil, err
	}
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return nil, err
	}
	if sess.inviteID == uuid.Nil || sess.tenantID == uuid.Nil {
		return nil, errs.ErrPasskeySessionInvalid
	}
	// The organisation may have switched passkeys off since the ceremony began.
	if err := s.passkeysAllowed(ctx, sess.tenantID); err != nil {
		return nil, err
	}
	userID, err := s.createUserFromSignup(ctx, sess, cred, name, func(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
		return s.invitations.AcceptForNewAccountTx(ctx, tx, sess.inviteID, sess.tenantID, userID, sess.email)
	})
	if errors.Is(err, errs.ErrAuthEmailExists) {
		// An account took the address after the ceremony began.
		return nil, errs.ErrInviteAccountExists
	}
	if err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, userID, sess.tenantID, ip, ua, "invite_accept")
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
