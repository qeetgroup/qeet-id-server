package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// BeginLogin starts a login ceremony. Every ceremony is discoverable, so the answer is the same
// whether or not email has an account or passkey; with an email, only that account's passkey can
// finish it. An email whose organization requires SSO is refused before lookup; such an account's
// passkey is refused when it finishes (verifyLogin).
func (s *Service) BeginLogin(ctx context.Context, email string) (uuid.UUID, *protocol.CredentialAssertion, error) {
	kind, owner := "login_discoverable", (*uuid.UUID)(nil)
	if email != "" {
		if err := s.refuseCaptured(ctx, email); err != nil {
			return uuid.Nil, nil, err
		}
		// A "login" ceremony with no owner is for an address with no account:
		// no passkey can finish it.
		kind = "login"
		id, err := s.q.GetUserIDByEmail(ctx, email)
		switch {
		case err == nil:
			owner = &id
		case !errors.Is(err, pgx.ErrNoRows):
			return uuid.Nil, nil, err
		}
	}
	options, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return uuid.Nil, nil, ErrCeremonyFailed.Wrap(err)
	}
	id, err := s.storeSession(ctx, owner, kind, sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishLogin verifies the assertion, updates the sign counter, and issues a
// Qeet session token pair for the authenticated user.
func (s *Service) FinishLogin(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, ip, ua string) (*auth.TokenPair, error) {
	userID, organizationID, err := s.verifyLogin(ctx, sessionID, credential)
	if err != nil {
		s.recordFailure(ctx, userID, organizationID, ip, ua, err)
		return nil, err
	}
	return s.auth.IssuePair(ctx, userID, organizationID, ip, ua, "passkey")
}

// recordFailure records a passkey sign-in refused for its ceremony or
// assertion as a failed sign-in, naming the account when it was identified.
// Errors that aren't a refusal (the store failing) aren't recorded.
func (s *Service) recordFailure(ctx context.Context, userID, organizationID uuid.UUID, ip, ua string, err error) {
	refusal := errs.As(err)
	if refusal == nil {
		return
	}
	s.auth.RecordSignInFailure(ctx, auth.SignInFailure{
		OrganizationID: organizationID, UserID: userID, Method: "passkey", Reason: refusal.Code, IP: ip, UserAgent: ua,
	})
}

// FinishLoginSession verifies the assertion, updates the sign counter, and
// opens a hosted-login SSO session for the authenticated user instead of
// issuing a token pair: it returns the user and the raw cookie value to set.
func (s *Service) FinishLoginSession(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, ip, ua string) (uuid.UUID, string, error) {
	userID, organizationID, err := s.verifyLogin(ctx, sessionID, credential)
	if err != nil {
		s.recordFailure(ctx, userID, organizationID, ip, ua, err)
		return uuid.Nil, "", err
	}
	raw, err := s.auth.CreatePasskeyLoginSession(ctx, userID, ip, ua)
	if err != nil {
		return uuid.Nil, "", err
	}
	return userID, raw, nil
}

// verifyLogin takes the login ceremony, verifies the assertion against it and
// updates the credential's sign counter, returning who signed in. On failure
// it returns the account (and its organization) when the ceremony or the
// assertion identified one.
func (s *Service) verifyLogin(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage) (uuid.UUID, uuid.UUID, error) {
	kind, sessUser, sessionData, err := takeSession(ctx, s.q, sessionID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return uuid.Nil, uuid.Nil, ErrAssertionInvalid
	}

	if kind != "login" && kind != "login_discoverable" {
		return uuid.Nil, uuid.Nil, ErrSessionInvalid
	}
	var resolved *webauthnUser
	var resolvedOrganization uuid.UUID
	var refused error
	// go-webauthn resolves the user before it checks the signature, so a
	// refusal here means the assertion is never verified. A ceremony begun for
	// an email takes only a passkey of that account.
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		uid, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, err
		}
		if kind == "login" && (sessUser == nil || *sessUser != uid) {
			return nil, ErrLoginFailed
		}
		u, tid, err := loadUser(ctx, s.q, uid)
		if err != nil {
			return nil, err
		}
		resolved, resolvedOrganization = u, tid
		if refused = s.passkeysAllowed(ctx, tid); refused != nil {
			return nil, refused
		}
		if refused = s.refuseCaptured(ctx, u.name); refused != nil {
			return nil, refused
		}
		return u, nil
	}
	cred, err := s.wa.ValidateDiscoverableLogin(handler, *sessionData, parsed)
	var who, whoOrganization uuid.UUID
	if resolved != nil {
		who, whoOrganization = resolved.id, resolvedOrganization
	}
	if refused != nil {
		return who, whoOrganization, refused
	}
	if err != nil || resolved == nil {
		return who, whoOrganization, ErrLoginFailed
	}
	loginUserID, organizationID := resolved.id, resolvedOrganization

	// A sign counter that failed to advance may mean a cloned authenticator.
	// go-webauthn flags it and leaves the response to the RP (WebAuthn L2 §6.1.1
	// step 17); refuse, or a copied key could keep signing in.
	if cred.Authenticator.CloneWarning {
		slog.Error("passkey signature counter regressed — possible cloned authenticator",
			"user_id", loginUserID,
			"organization_id", organizationID,
			"credential_id", base64.RawURLEncoding.EncodeToString(cred.ID),
			"asserted_sign_count", cred.Authenticator.SignCount,
		)
		return loginUserID, organizationID, ErrCloneDetected
	}
	if err := s.q.UpdatePasskeySignCount(ctx, dbgen.UpdatePasskeySignCountParams{
		SignCount:    int64(cred.Authenticator.SignCount),
		BackupState:  cred.Flags.BackupState,
		CredentialID: cred.ID,
	}); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return loginUserID, organizationID, nil
}
