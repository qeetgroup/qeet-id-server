package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
)

const sessionTTL = 5 * time.Minute

// webauthnUser adapts a Qeet user to the go-webauthn User interface.
type webauthnUser struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte { b := u.id; return b[:] }

func (u *webauthnUser) WebAuthnName() string { return u.name }

func (u *webauthnUser) WebAuthnDisplayName() string { return u.displayName }

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

// loadUser builds a webauthnUser (with stored credentials), read through q,
// and returns the user's organization id (uuid.Nil when organization-less).
func loadUser(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) (*webauthnUser, uuid.UUID, error) {
	row, err := q.GetUserForWebAuthn(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, ErrUserNotFound
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	creds, err := loadCredentials(ctx, q, userID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	dn := row.Email
	if row.DisplayName != nil && *row.DisplayName != "" {
		dn = *row.DisplayName
	}
	var tid uuid.UUID
	if row.OrganizationID != nil {
		tid = *row.OrganizationID
	}
	return &webauthnUser{id: userID, name: row.Email, displayName: dn, creds: creds}, tid, nil
}

func loadCredentials(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) ([]webauthn.Credential, error) {
	rows, err := q.GetPasskeyCredentialsForCeremony(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]webauthn.Credential, 0, len(rows))
	for _, m := range rows {
		c := webauthn.Credential{ID: m.CredentialID, PublicKey: m.PublicKey}
		c.Authenticator.SignCount = uint32(m.SignCount) // #nosec G115 -- stored from a uint32
		// go-webauthn rejects a login whose backup-eligible flag differs from
		// the stored one, so synced passkeys need the flags they registered with.
		c.Flags.BackupEligible = m.BackupEligible
		c.Flags.BackupState = m.BackupState
		if m.Aaguid != nil {
			b := *m.Aaguid
			c.Authenticator.AAGUID = b[:]
		}
		for _, t := range m.Transports {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		out = append(out, c)
	}
	return out, nil
}

// storeSession persists in-flight ceremony state and returns its opaque id.
func (s *RelyingParty) storeSession(ctx context.Context, userID *uuid.UUID, kind string, data *webauthn.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	return s.q.InsertWebAuthnSession(ctx, dbgen.InsertWebAuthnSessionParams{
		UserID:    userID,
		Kind:      kind,
		Data:      raw,
		ExpiresAt: time.Now().UTC().Add(sessionTTL),
	})
}

// takeSession reads and deletes a ceremony session (single-use) through q.
func takeSession(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (kind string, userID *uuid.UUID, data *webauthn.SessionData, err error) {
	row, err := q.TakeWebAuthnSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil, ErrAuthSessionExpired
	}
	if err != nil {
		return "", nil, nil, err
	}
	if time.Now().After(row.ExpiresAt) {
		return "", nil, nil, ErrAuthSessionExpired
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(row.Data, &sd); err != nil {
		return "", nil, nil, err
	}
	return row.Kind, row.UserID, &sd, nil
}
