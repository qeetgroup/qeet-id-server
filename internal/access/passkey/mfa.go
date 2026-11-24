package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
)

// Passkeys as a second factor: BeginMFA and FinishMFA assert a signed-in
// user's existing passkeys to prove recent possession of one. Unlike sign-in,
// they issue no tokens, so the relying party answers them alone.

// BeginMFA starts a second-factor assertion ceremony for an authenticated user.
// It errors if the user has no registered credentials, and binds the ceremony
// session to the user via a distinct "mfa" kind so a login session can't be
// replayed here (and vice versa).
func (s *RelyingParty) BeginMFA(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialAssertion, error) {
	u, _, err := loadUser(ctx, s.q, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if len(u.creds) == 0 {
		return uuid.Nil, nil, ErrNoCredentials
	}
	options, sessionData, err := s.wa.BeginLogin(u)
	if err != nil {
		return uuid.Nil, nil, ErrCeremonyFailed.Wrap(err)
	}
	id, err := s.storeSession(ctx, &userID, "mfa", sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishMFA verifies a second-factor assertion against the authenticated user's
// own credentials. The ceremony session must be of kind "mfa" and bound to the
// same userID; both checks reject cross-user/cross-flow replay. On success it
// updates the credential's sign counter and returns nil — no token is issued.
func (s *RelyingParty) FinishMFA(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	return s.finishMFA(ctx, s.q, userID, sessionID, credential)
}

// FinishMFATx is FinishMFA inside the caller's transaction: the ceremony
// session is taken, the user loaded and the sign counter updated through tx.
func (s *RelyingParty) FinishMFATx(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	return s.finishMFA(ctx, s.q.WithTx(tx), userID, sessionID, credential)
}

func (s *RelyingParty) finishMFA(ctx context.Context, q *dbgen.Queries, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	kind, sessUser, sessionData, err := takeSession(ctx, q, sessionID)
	if err != nil {
		return err
	}
	if kind != "mfa" || sessUser == nil || *sessUser != userID {
		return ErrSessionMismatch
	}
	u, _, err := loadUser(ctx, q, userID)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return ErrAssertionInvalid
	}
	cred, err := s.wa.ValidateLogin(u, *sessionData, parsed)
	if err != nil {
		return ErrMFAFailed
	}
	// See verifyLogin: a counter that fails to advance signals a cloned
	// credential, and a second factor is exactly where that must not pass.
	if cred.Authenticator.CloneWarning {
		slog.Error("passkey signature counter regressed during MFA — possible cloned authenticator",
			"user_id", userID,
			"credential_id", base64.RawURLEncoding.EncodeToString(cred.ID),
			"asserted_sign_count", cred.Authenticator.SignCount,
		)
		return ErrCloneDetected
	}
	if err := q.UpdatePasskeySignCount(ctx, dbgen.UpdatePasskeySignCountParams{
		SignCount:    int64(cred.Authenticator.SignCount),
		BackupState:  cred.Flags.BackupState,
		CredentialID: cred.ID,
	}); err != nil {
		return err
	}
	return nil
}
