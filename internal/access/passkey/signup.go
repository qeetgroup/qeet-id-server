package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Passkey-first signup. No user row exists until the ceremony finishes, so the
// session carries a generated WebAuthn user ID and the pending account details.
// The account is created with that ID, which the authenticator returns as the
// user handle at every sign-in.

// signupSession is a decoded pending-signup ceremony. inviteID is the
// invitation it accepts (uuid.Nil for an ordinary sign-up).
type signupSession struct {
	subjectID      uuid.UUID
	email          string
	displayName    string
	organizationID uuid.UUID
	inviteID       uuid.UUID
	data           *webauthn.SessionData
}

// storeSignupSession persists an in-flight pre-account registration ceremony.
// organizationID is uuid.Nil for an organization-less signup, and inviteID when it accepts
// no invitation.
func (s *Service) storeSignupSession(ctx context.Context, subjectID uuid.UUID, email, displayName string, organizationID, inviteID uuid.UUID, data *webauthn.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	var dnPtr *string
	if displayName != "" {
		dnPtr = &displayName
	}
	organizationPG := postgres.NullIfZero(organizationID)
	return s.q.InsertSignupWebAuthnSession(ctx, dbgen.InsertSignupWebAuthnSessionParams{
		Data:                  raw,
		ExpiresAt:             time.Now().UTC().Add(sessionTTL),
		SubjectID:             &subjectID,
		PendingEmail:          &email,
		PendingDisplayName:    dnPtr,
		PendingOrganizationID: organizationPG,
		InviteID:              postgres.NullIfZero(inviteID),
	})
}

// takeSignupSession reads and deletes a pending-signup ceremony (single-use).
func (s *Service) takeSignupSession(ctx context.Context, id uuid.UUID) (*signupSession, error) {
	row, err := s.q.TakeSignupWebAuthnSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAuthSessionExpired
	}
	if err != nil {
		return nil, err
	}
	if row.Kind != "signup" || row.SubjectID == nil || row.PendingEmail == nil {
		return nil, ErrSessionInvalid
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, ErrAuthSessionExpired
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(row.Data, &sd); err != nil {
		return nil, err
	}
	sess := &signupSession{
		subjectID: postgres.ZeroIfNull(row.SubjectID),
		email:     *row.PendingEmail,
		data:      &sd,
	}
	if row.PendingDisplayName != nil {
		sess.displayName = *row.PendingDisplayName
	}
	if row.PendingOrganizationID != nil {
		sess.organizationID = *row.PendingOrganizationID
	}
	if row.PendingInviteID != nil {
		sess.inviteID = *row.PendingInviteID
	}
	return sess, nil
}

// BeginSignup starts a passkey-founded registration ceremony for a brand-new,
// organization-less account — the passwordless counterpart to authentication.Service.Signup.
func (s *Service) BeginSignup(ctx context.Context, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	return s.beginSignup(ctx, uuid.Nil, email, displayName)
}

// BeginOrganizationSignup starts the same ceremony for an organization's hosted signup, the
// passwordless authentication.Service.RegisterInOrganization. It is refused unless the organization
// allows self-registration and passkeys.
func (s *Service) BeginOrganizationSignup(ctx context.Context, organizationID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	enabled, err := s.auth.SelfRegistrationEnabled(ctx, organizationID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if !enabled {
		return uuid.Nil, nil, errs.ErrAuthSelfRegistrationDisabled
	}
	if err := s.passkeysAllowed(ctx, organizationID); err != nil {
		return uuid.Nil, nil, err
	}
	return s.beginSignup(ctx, organizationID, email, displayName)
}

func (s *Service) beginSignup(ctx context.Context, organizationID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	return s.beginSignupFor(ctx, organizationID, uuid.Nil, email, displayName)
}

// beginSignupFor starts a passkey sign-up ceremony for email in organizationID,
// accepting inviteID (uuid.Nil: none). It answers alike whether or not the
// address has an account and claims nothing: a taken address, and one on a
// domain another organization manages, are refused when the ceremony finishes.
func (s *Service) beginSignupFor(ctx context.Context, organizationID, inviteID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return uuid.Nil, nil, errs.ErrAuthEmailRequired
	}
	// An address whose organization requires single sign-on gets its account
	// from the identity provider; an invitation was checked when it was opened.
	if inviteID == uuid.Nil {
		if err := s.refuseCaptured(ctx, email); err != nil {
			return uuid.Nil, nil, err
		}
	}

	// subjectID is the WebAuthn user ID the passkey is registered under, and
	// becomes the new user's id in createUserFromSignup (no row exists yet).
	subjectID := uuid.New()
	dn := displayName
	if dn == "" {
		dn = email
	}
	u := &webauthnUser{id: subjectID, name: email, displayName: dn}
	options, sessionData, err := s.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return uuid.Nil, nil, ErrCeremonyFailed.Wrap(err)
	}
	id, err := s.storeSignupSession(ctx, subjectID, email, displayName, organizationID, inviteID, sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishSignup verifies the attestation, creates the organization-less user with the
// passkey as its founding credential (no password), and signs them in. The
// passkey is named as in FinishRegister.
func (s *Service) FinishSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (*authentication.TokenPair, uuid.UUID, error) {
	name, err := enrolmentName(name, ua)
	if err != nil {
		return nil, uuid.Nil, err
	}
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return nil, uuid.Nil, err
	}
	// A ceremony that accepts an invitation finishes only through
	// FinishInviteSignup, which grants the invited role and consumes it.
	if sess.inviteID != uuid.Nil {
		return nil, uuid.Nil, ErrSessionInvalid
	}
	if err := domainverify.CheckNewAccount(ctx, s.pool, sess.organizationID, sess.email); err != nil {
		return nil, uuid.Nil, err
	}
	userID, err := s.createUserFromSignup(ctx, sess, cred, name, nil)
	if err != nil {
		return nil, uuid.Nil, err
	}
	pair, err := s.auth.IssuePair(ctx, userID, uuid.Nil, ip, ua, "passkey")
	if err != nil {
		return nil, uuid.Nil, err
	}
	return pair, userID, nil
}

// FinishOrganizationSignup is FinishSignup for an organization's hosted signup: it creates
// the user in sess's organization and returns a hosted-login SSO cookie value instead
// of a token pair, as authentication.Service.RegisterInOrganization does.
func (s *Service) FinishOrganizationSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (uuid.UUID, string, error) {
	name, err := enrolmentName(name, ua)
	if err != nil {
		return uuid.Nil, "", err
	}
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return uuid.Nil, "", err
	}
	if sess.organizationID == uuid.Nil || sess.inviteID != uuid.Nil {
		return uuid.Nil, "", ErrSessionInvalid
	}
	// The organization may have switched passkeys off since the ceremony began.
	if err := s.passkeysAllowed(ctx, sess.organizationID); err != nil {
		return uuid.Nil, "", err
	}
	// On a domain another organization manages, only it creates accounts.
	if err := domainverify.CheckNewAccount(ctx, s.pool, sess.organizationID, sess.email); err != nil {
		return uuid.Nil, "", err
	}
	userID, err := s.createUserFromSignup(ctx, sess, cred, name, nil)
	if err != nil {
		return uuid.Nil, "", err
	}
	raw, err := s.auth.CreatePasskeyLoginSession(ctx, userID, ip, ua)
	if err != nil {
		return uuid.Nil, "", err
	}
	return userID, raw, nil
}

// verifySignupAttestation takes the ceremony session and verifies the
// attestation against the ephemeral subject used at Begin time.
func (s *Service) verifySignupAttestation(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage) (*signupSession, *webauthn.Credential, error) {
	sess, err := s.takeSignupSession(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	dn := sess.displayName
	if dn == "" {
		dn = sess.email
	}
	u := &webauthnUser{id: sess.subjectID, name: sess.email, displayName: dn}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credential))
	if err != nil {
		return nil, nil, ErrAttestationInvalid
	}
	cred, err := s.wa.CreateCredential(u, *sess.data, parsed)
	if err != nil {
		return nil, nil, ErrAttestationInvalid.Wrap(err)
	}
	return sess, cred, nil
}

// createUserFromSignup inserts the user row (no password credential) and
// attaches the verified passkey as its founding credential, atomically. within
// (may be nil) runs in the same transaction once both exist; its error undoes
// everything.
func (s *Service) createUserFromSignup(ctx context.Context, sess *signupSession, cred *webauthn.Credential, name string, within func(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	qtx := s.q.WithTx(tx)

	organizationPG := postgres.NullIfZero(sess.organizationID)
	var dnPtr *string
	if sess.displayName != "" {
		dnPtr = &sess.displayName
	}
	userID, err := qtx.InsertUserFromSignup(ctx, dbgen.InsertUserFromSignupParams{
		ID:             sess.subjectID,
		OrganizationID: organizationPG,
		Email:          sess.email,
		DisplayName:    dnPtr,
	})
	if err != nil {
		if postgres.IsUnique(err) {
			return uuid.Nil, errs.ErrAuthEmailExists
		}
		return uuid.Nil, err
	}

	var aaguidPG *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if g, gerr := uuid.FromBytes(cred.Authenticator.AAGUID); gerr == nil && g != uuid.Nil {
			aaguidPG = &g
		}
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	if _, err := qtx.InsertPasskeyCredential(ctx, dbgen.InsertPasskeyCredentialParams{
		UserID:         userID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      int64(cred.Authenticator.SignCount),
		Aaguid:         aaguidPG,
		Transports:     transports,
		Name:           &name,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}); err != nil {
		if postgres.IsUnique(err) {
			return uuid.Nil, ErrExists
		}
		return uuid.Nil, err
	}
	if within != nil {
		if err := within(ctx, tx, userID); err != nil {
			return uuid.Nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}
