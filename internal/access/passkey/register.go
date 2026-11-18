package passkey

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// BeginRegister starts a registration ceremony for an authenticated user,
// unless their organization has passkeys switched off.
func (s *Service) BeginRegister(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialCreation, error) {
	u, organizationID, err := loadUser(ctx, s.q, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if err := s.passkeysAllowed(ctx, organizationID); err != nil {
		return uuid.Nil, nil, err
	}
	// Discoverable credentials, so usernameless sign-in can find them. UV is
	// Required because go-webauthn checks the UV flag only then; otherwise a
	// passkey could sign in on possession alone. This deliberately refuses
	// PIN-less hardware keys.
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
	id, err := s.storeSession(ctx, &userID, "register", sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishRegister verifies the attestation and stores the new credential, named
// name or, if empty, after who's browser; the addition is recorded as who's and
// the account holder told. The name is checked before the ceremony is spent,
// so a refused name can be corrected and retried; the organization's passkey
// setting is checked again in case it was switched off.
func (s *Service) FinishRegister(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage, name string, who Requester) error {
	name, err := enrolmentName(name, who.UserAgent)
	if err != nil {
		return err
	}
	u, organizationID, err := loadUser(ctx, s.q, userID)
	if err != nil {
		return err
	}
	if err := s.passkeysAllowed(ctx, organizationID); err != nil {
		return err
	}
	kind, sessUser, sessionData, err := takeSession(ctx, s.q, sessionID)
	if err != nil {
		return err
	}
	if kind != "register" || sessUser == nil || *sessUser != userID {
		return ErrSessionMismatch
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credential))
	if err != nil {
		return ErrAttestationInvalid
	}
	cred, err := s.wa.CreateCredential(u, *sessionData, parsed)
	if err != nil {
		return ErrAttestationInvalid.Wrap(err)
	}
	return s.insertCredential(ctx, userID, cred, name, who)
}

// insertCredential stores a verified credential for userID with its audit
// record, then tells the account holder.
func (s *Service) insertCredential(ctx context.Context, userID uuid.UUID, cred *webauthn.Credential, name string, who Requester) error {
	var aaguidPG *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if g, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil && g != uuid.Nil {
			aaguidPG = &g
		}
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	id, err := s.q.WithTx(tx).InsertPasskeyCredential(ctx, dbgen.InsertPasskeyCredentialParams{
		UserID:         userID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      int64(cred.Authenticator.SignCount),
		Aaguid:         aaguidPG,
		Transports:     transports,
		Name:           &name,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	})
	if err != nil {
		if postgres.IsUnique(err) {
			return ErrExists
		}
		return err
	}
	if err := audit.Record(ctx, tx, who.event("passkey.registered", userID,
		map[string]any{"passkey_id": id, "name": name})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.tellPasskeyChange(ctx, userID, passkeyAdded, name)
	return nil
}
