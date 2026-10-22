// Package passkey implements WebAuthn passkey registration and login on top of
// go-webauthn. The credential store (auth.passkey_credentials) backs
// list/rename/delete and the ceremony; in-flight challenges live in
// auth.webauthn_sessions.
package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkeys/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const sessionTTL = 5 * time.Minute

type Credential struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       *string    `json:"name"`
	Transports []string   `json:"transports"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	wa   *webauthn.WebAuthn
	auth *auth.Service
	// policy says whether an organization permits passkeys (nil = no
	// restriction). Set via SetMethodPolicy.
	policy MethodPolicy
	// invitations lets an invited person found their account on a passkey
	// (nil = that path is off). Set via SetInvitations; see invite.go.
	invitations InvitationAcceptor
}

func NewService(pool *pgxpool.Pool, wa *webauthn.WebAuthn, authSvc *auth.Service) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), wa: wa, auth: authSvc}
}

// MethodPolicy is the slice of the tenant authentication policy the passkey
// service needs. Satisfied by *authpolicy.Service; an interface so this package
// doesn't import authpolicy. Wired in internal/bootstrap/dependencies.go.
type MethodPolicy interface {
	PasskeyEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// SetMethodPolicy wires the tenant's passkey on/off setting.
func (s *Service) SetMethodPolicy(p MethodPolicy) { s.policy = p }

// passkeysAllowed is the one place the tenant's passkey_enabled setting is
// read: adding a passkey is offered (EnrolmentAllowed) and accepted
// (BeginRegister, FinishRegister), and signing in with one is accepted
// (FinishLogin, before the assertion is verified), only when it allows them. tenantID is the
// user's own organization, read from the database; uuid.Nil (a user without
// an organization) has no policy and is not restricted.
func (s *Service) passkeysAllowed(ctx context.Context, tenantID uuid.UUID) error {
	if tenantID == uuid.Nil || s.policy == nil {
		return nil
	}
	enabled, err := s.policy.PasskeyEnabled(ctx, tenantID)
	if err != nil {
		return err
	}
	if !enabled {
		return errs.ErrPasskeyDisabled
	}
	return nil
}

// EnrolmentAllowed reports whether the user may add a passkey: false when
// their organization has passkeys switched off.
func (s *Service) EnrolmentAllowed(ctx context.Context, userID uuid.UUID) (bool, error) {
	row, err := s.q.GetUserForWebAuthn(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, errs.ErrPasskeyUserNotFound
	}
	if err != nil {
		return false, err
	}
	var tenantID uuid.UUID
	if row.TenantID.Valid {
		tenantID = uuid.UUID(row.TenantID.Bytes)
	}
	err = s.passkeysAllowed(ctx, tenantID)
	if errors.Is(err, errs.ErrPasskeyDisabled) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	rows, err := s.q.ListPasskeyCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rows))
	for _, m := range rows {
		out = append(out, credentialFromRow(m))
	}
	return out, nil
}

func credentialFromRow(m dbgen.ListPasskeyCredentialsRow) Credential {
	var lastUsedAt *time.Time
	if m.LastUsedAt.Valid {
		t := m.LastUsedAt.Time
		lastUsedAt = &t
	}
	return Credential{
		ID:         m.ID,
		UserID:     m.UserID,
		Name:       m.Name,
		Transports: m.Transports,
		LastUsedAt: lastUsedAt,
		CreatedAt:  m.CreatedAt,
	}
}

// Rename sets the name of one of the user's passkeys. The name is cleaned and
// checked (see validName). Like Delete it is scoped to the owner: another
// user's passkey is not found, and is left unchanged.
func (s *Service) Rename(ctx context.Context, id, userID uuid.UUID, name string) (*Credential, error) {
	name, err := validName(name)
	if err != nil {
		return nil, err
	}
	row, err := s.q.RenamePasskeyCredential(ctx, dbgen.RenamePasskeyCredentialParams{
		Name:   &name,
		ID:     id,
		UserID: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := credentialFromRow(dbgen.ListPasskeyCredentialsRow(row))
	return &c, nil
}

// Delete is scoped to the owner so one user can't delete another's passkey.
// Delete removes one of the user's own passkeys. ErrNotFound when it is not
// theirs (nothing is deleted); ErrAuthLastSignInMethod, recorded, when it is
// their account's only way to sign in.
func (s *Service) Delete(ctx context.Context, id, userID uuid.UUID, by user.Remover) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, userID)
	if err != nil {
		return err
	}
	n, err := s.q.WithTx(tx).DeletePasskeyCredential(ctx, dbgen.DeletePasskeyCredentialParams{
		ID:     id,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		return user.RefuseLastMethodRemoval(ctx, s.pool, userID, nil, "passkey", id, by)
	}
	return tx.Commit(ctx)
}

// --- WebAuthn ceremony ---

// webauthnUser adapts a Qeet user to the go-webauthn User interface.
type webauthnUser struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte          { b := u.id; return b[:] }
func (u *webauthnUser) WebAuthnName() string        { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

// loadUser builds a webauthnUser (with stored credentials) and returns the
// user's tenant id (uuid.Nil when tenant-less).
func (s *Service) loadUser(ctx context.Context, userID uuid.UUID) (*webauthnUser, uuid.UUID, error) {
	row, err := s.q.GetUserForWebAuthn(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, errs.ErrPasskeyUserNotFound
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	creds, err := s.loadCredentials(ctx, userID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	dn := row.Email
	if row.DisplayName != nil && *row.DisplayName != "" {
		dn = *row.DisplayName
	}
	var tid uuid.UUID
	if row.TenantID.Valid {
		tid = uuid.UUID(row.TenantID.Bytes)
	}
	return &webauthnUser{id: userID, name: row.Email, displayName: dn, creds: creds}, tid, nil
}

func (s *Service) loadUserByEmail(ctx context.Context, email string) (*webauthnUser, uuid.UUID, error) {
	id, err := s.q.GetUserIDByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, errs.ErrPasskeyUserNotFound
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	return s.loadUser(ctx, id)
}

func (s *Service) loadCredentials(ctx context.Context, userID uuid.UUID) ([]webauthn.Credential, error) {
	rows, err := s.q.GetPasskeyCredentialsForCeremony(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]webauthn.Credential, 0, len(rows))
	for _, m := range rows {
		c := webauthn.Credential{ID: m.CredentialID, PublicKey: m.PublicKey}
		c.Authenticator.SignCount = uint32(m.SignCount)
		// go-webauthn rejects a login whose backup-eligible flag differs from
		// the stored one, so synced passkeys need the flags they registered with.
		c.Flags.BackupEligible = m.BackupEligible
		c.Flags.BackupState = m.BackupState
		if m.Aaguid.Valid {
			b := uuid.UUID(m.Aaguid.Bytes)
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
func (s *Service) storeSession(ctx context.Context, userID *uuid.UUID, kind string, data *webauthn.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	var uidPG pgtype.UUID
	if userID != nil {
		uidPG = pgtype.UUID{Bytes: *userID, Valid: true}
	}
	return s.q.InsertWebAuthnSession(ctx, dbgen.InsertWebAuthnSessionParams{
		UserID:    uidPG,
		Kind:      kind,
		Data:      raw,
		ExpiresAt: time.Now().UTC().Add(sessionTTL),
	})
}

// takeSession reads and deletes a ceremony session (single-use).
func (s *Service) takeSession(ctx context.Context, id uuid.UUID) (kind string, userID *uuid.UUID, data *webauthn.SessionData, err error) {
	row, err := s.q.TakeWebAuthnSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil, errs.ErrAuthSessionExpired
	}
	if err != nil {
		return "", nil, nil, err
	}
	if time.Now().After(row.ExpiresAt) {
		return "", nil, nil, errs.ErrAuthSessionExpired
	}
	var uid *uuid.UUID
	if row.UserID.Valid {
		u := uuid.UUID(row.UserID.Bytes)
		uid = &u
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(row.Data, &sd); err != nil {
		return "", nil, nil, err
	}
	return row.Kind, uid, &sd, nil
}

// BeginRegister starts a registration ceremony for an authenticated user,
// unless their organization has passkeys switched off.
func (s *Service) BeginRegister(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialCreation, error) {
	u, tenantID, err := s.loadUser(ctx, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if err := s.passkeysAllowed(ctx, tenantID); err != nil {
		return uuid.Nil, nil, err
	}
	// Require a discoverable (resident) credential so the passwordless,
	// usernameless login flow (BeginDiscoverableLogin) can find it — passkeys
	// registered without this aren't discoverable and break login on the hosted
	// app.
	//
	// UV is Required, not Preferred: go-webauthn only checks the UV flag when
	// the value is exactly Required, so "preferred" meant it was never verified
	// at all. Enrolling a credential that cannot do user verification would
	// otherwise produce a passkey that logs in on possession alone. The cost is
	// that a PIN-less hardware key can no longer be enrolled; for a
	// passkeys-first IdP that is the intended trade.
	options, sessionData, err := s.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
	}
	id, err := s.storeSession(ctx, &userID, "register", sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishRegister verifies the attestation and persists the new credential,
// named name or, when that is empty, after the browser in userAgent. The name
// is checked before the ceremony session is used, so a refused name can be
// corrected and the same ceremony finished. The organization's passkey setting
// is checked again, so a ceremony begun before passkeys were switched off
// cannot be finished.
func (s *Service) FinishRegister(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage, name, userAgent string) error {
	name, err := enrolmentName(name, userAgent)
	if err != nil {
		return err
	}
	u, tenantID, err := s.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.passkeysAllowed(ctx, tenantID); err != nil {
		return err
	}
	kind, sessUser, sessionData, err := s.takeSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if kind != "register" || sessUser == nil || *sessUser != userID {
		return errs.ErrPasskeySessionMismatch
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credential))
	if err != nil {
		return errs.ErrPasskeyAttestationInvalid
	}
	cred, err := s.wa.CreateCredential(u, *sessionData, parsed)
	if err != nil {
		return errs.ErrPasskeyAttestationInvalid.Wrap(err)
	}
	return s.insertCredential(ctx, userID, cred, name)
}

func (s *Service) insertCredential(ctx context.Context, userID uuid.UUID, cred *webauthn.Credential, name string) error {
	var aaguidPG pgtype.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if g, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil && g != uuid.Nil {
			aaguidPG = pgtype.UUID{Bytes: g, Valid: true}
		}
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	err := s.q.InsertPasskeyCredential(ctx, dbgen.InsertPasskeyCredentialParams{
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
		if pgxerr.IsUnique(err) {
			return errs.ErrPasskeyExists
		}
		return err
	}
	return nil
}

// --- Passkey-first signup (no existing user/password required) ---
//
// BeginSignup/FinishSignup and BeginTenantSignup/FinishTenantSignup let a
// brand-new account be founded on a passkey instead of a password. Since no
// user row exists yet at Begin time, the ceremony carries a pre-generated
// "subject" WebAuthn ID plus the pending account details in
// auth.webauthn_sessions (subject_id/pending_*) rather than a real user_id.
// The user row (and its passkey credential) is only created once FinishSignup
// verifies the attestation — and it is created WITH the subject ID as its id:
// the authenticator stores that ID and returns it as the user handle on every
// sign-in, so the account must answer to it.

// signupSession is a decoded pending-signup ceremony. inviteID is the
// invitation it accepts (uuid.Nil for an ordinary sign-up).
type signupSession struct {
	subjectID   uuid.UUID
	email       string
	displayName string
	tenantID    uuid.UUID
	inviteID    uuid.UUID
	data        *webauthn.SessionData
}

// storeSignupSession persists an in-flight pre-account registration ceremony.
// tenantID is uuid.Nil for a tenant-less (direct) signup, inviteID for one
// that accepts no invitation.
func (s *Service) storeSignupSession(ctx context.Context, subjectID uuid.UUID, email, displayName string, tenantID, inviteID uuid.UUID, data *webauthn.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	var dnPtr *string
	if displayName != "" {
		dnPtr = &displayName
	}
	tenantPG := pgtype.UUID{}
	if tenantID != uuid.Nil {
		tenantPG = pgtype.UUID{Bytes: tenantID, Valid: true}
	}
	return s.q.InsertSignupWebAuthnSession(ctx, dbgen.InsertSignupWebAuthnSessionParams{
		Data:               raw,
		ExpiresAt:          time.Now().UTC().Add(sessionTTL),
		SubjectID:          pgtype.UUID{Bytes: subjectID, Valid: true},
		PendingEmail:       &email,
		PendingDisplayName: dnPtr,
		PendingTenantID:    tenantPG,
		InviteID:           pgtype.UUID{Bytes: inviteID, Valid: inviteID != uuid.Nil},
	})
}

// takeSignupSession reads and deletes a pending-signup ceremony (single-use).
func (s *Service) takeSignupSession(ctx context.Context, id uuid.UUID) (*signupSession, error) {
	row, err := s.q.TakeSignupWebAuthnSession(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAuthSessionExpired
	}
	if err != nil {
		return nil, err
	}
	if row.Kind != "signup" || !row.SubjectID.Valid || row.PendingEmail == nil {
		return nil, errs.ErrPasskeySessionInvalid
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errs.ErrAuthSessionExpired
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(row.Data, &sd); err != nil {
		return nil, err
	}
	sess := &signupSession{
		subjectID: uuid.UUID(row.SubjectID.Bytes),
		email:     *row.PendingEmail,
		data:      &sd,
	}
	if row.PendingDisplayName != nil {
		sess.displayName = *row.PendingDisplayName
	}
	if row.PendingTenantID.Valid {
		sess.tenantID = uuid.UUID(row.PendingTenantID.Bytes)
	}
	if row.PendingInviteID.Valid {
		sess.inviteID = uuid.UUID(row.PendingInviteID.Bytes)
	}
	return sess, nil
}

// BeginSignup starts a passkey-founded registration ceremony for a brand-new,
// tenant-less account — the passwordless counterpart to auth.Service.Signup.
func (s *Service) BeginSignup(ctx context.Context, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	return s.beginSignup(ctx, uuid.Nil, email, displayName)
}

// BeginTenantSignup starts the same ceremony scoped to a tenant's hosted
// signup flow — the passwordless counterpart to auth.Service.RegisterInTenant.
// Gated by the same self_registration_enabled policy, and refused with
// ErrPasskeyDisabled, before a ceremony starts, where the tenant has passkeys
// off.
func (s *Service) BeginTenantSignup(ctx context.Context, tenantID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	enabled, err := s.auth.SelfRegistrationEnabled(ctx, tenantID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if !enabled {
		return uuid.Nil, nil, errs.ErrAuthSelfRegistrationDisabled
	}
	if err := s.passkeysAllowed(ctx, tenantID); err != nil {
		return uuid.Nil, nil, err
	}
	return s.beginSignup(ctx, tenantID, email, displayName)
}

func (s *Service) beginSignup(ctx context.Context, tenantID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	return s.beginSignupFor(ctx, tenantID, uuid.Nil, email, displayName)
}

// beginSignupFor starts a passkey sign-up ceremony for email in tenantID,
// accepting inviteID (uuid.Nil: none).
func (s *Service) beginSignupFor(ctx context.Context, tenantID, inviteID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return uuid.Nil, nil, errs.ErrAuthEmailRequired
	}
	// Conflict if the email is already taken by a real user, OR if a passkey
	// signup is already in flight for it (a non-expired pending session). The
	// two-phase begin→finish ceremony means no "user".users row exists until
	// FinishSignup, so without the second check a duplicate/rival signup for
	// an in-progress email would slip through (QID-14) — password signup, which
	// creates the row synchronously, has no such window. Scoped to non-expired
	// sessions (5-min TTL) so an abandoned ceremony can't lock the email out.
	var existsPtr *bool
	var err error
	switch {
	case inviteID != uuid.Nil:
		// The invitation was checked for an existing account, and only its
		// holder can begin it; the unique email still decides at the end.
	case tenantID == uuid.Nil:
		existsPtr, err = s.q.CheckEmailExistsNoTenant(ctx, email)
	default:
		existsPtr, err = s.q.CheckEmailExistsForTenant(ctx, dbgen.CheckEmailExistsForTenantParams{
			Lower:    email,
			TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		})
	}
	if err != nil {
		return uuid.Nil, nil, err
	}
	if existsPtr != nil && *existsPtr {
		return uuid.Nil, nil, errs.ErrAuthEmailExists
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
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
	}
	id, err := s.storeSignupSession(ctx, subjectID, email, displayName, tenantID, inviteID, sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishSignup verifies the attestation, creates the tenant-less user with the
// passkey as its founding credential (no password), and signs them in. The
// passkey is named as in FinishRegister.
func (s *Service) FinishSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (*auth.TokenPair, uuid.UUID, error) {
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
		return nil, uuid.Nil, errs.ErrPasskeySessionInvalid
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

// FinishTenantSignup is FinishSignup's tenant-scoped counterpart: it creates
// the user inside sess's tenant and returns a hosted-login SSO cookie value
// (via auth.Service.CreateLoginSession) instead of a bearer token pair,
// mirroring auth.Service.RegisterInTenant.
func (s *Service) FinishTenantSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (uuid.UUID, string, error) {
	name, err := enrolmentName(name, ua)
	if err != nil {
		return uuid.Nil, "", err
	}
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return uuid.Nil, "", err
	}
	if sess.tenantID == uuid.Nil || sess.inviteID != uuid.Nil {
		return uuid.Nil, "", errs.ErrPasskeySessionInvalid
	}
	// The organisation may have switched passkeys off since the ceremony began.
	if err := s.passkeysAllowed(ctx, sess.tenantID); err != nil {
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
		return nil, nil, errs.ErrPasskeyAttestationInvalid
	}
	cred, err := s.wa.CreateCredential(u, *sess.data, parsed)
	if err != nil {
		return nil, nil, errs.ErrPasskeyAttestationInvalid.Wrap(err)
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

	tenantPG := pgtype.UUID{}
	if sess.tenantID != uuid.Nil {
		tenantPG = pgtype.UUID{Bytes: sess.tenantID, Valid: true}
	}
	var dnPtr *string
	if sess.displayName != "" {
		dnPtr = &sess.displayName
	}
	userID, err := qtx.InsertUserFromSignup(ctx, dbgen.InsertUserFromSignupParams{
		ID:          sess.subjectID,
		TenantID:    tenantPG,
		Email:       sess.email,
		DisplayName: dnPtr,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return uuid.Nil, errs.ErrAuthEmailExists
		}
		return uuid.Nil, err
	}

	var aaguidPG pgtype.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if g, gerr := uuid.FromBytes(cred.Authenticator.AAGUID); gerr == nil && g != uuid.Nil {
			aaguidPG = pgtype.UUID{Bytes: g, Valid: true}
		}
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	if err := qtx.InsertPasskeyCredential(ctx, dbgen.InsertPasskeyCredentialParams{
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
		if pgxerr.IsUnique(err) {
			return uuid.Nil, errs.ErrPasskeyExists
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

// BeginLogin starts a login ceremony. An empty email triggers a discoverable
// (usernameless) flow; otherwise the user's registered credentials scope it.
func (s *Service) BeginLogin(ctx context.Context, email string) (uuid.UUID, *protocol.CredentialAssertion, error) {
	if email == "" {
		options, sessionData, err := s.wa.BeginDiscoverableLogin()
		if err != nil {
			return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
		}
		id, err := s.storeSession(ctx, nil, "login_discoverable", sessionData)
		if err != nil {
			return uuid.Nil, nil, err
		}
		return id, options, nil
	}
	u, _, err := s.loadUserByEmail(ctx, email)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if len(u.creds) == 0 {
		return uuid.Nil, nil, errs.ErrPasskeyNoCredentials
	}
	options, sessionData, err := s.wa.BeginLogin(u)
	if err != nil {
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
	}
	uid := u.id
	id, err := s.storeSession(ctx, &uid, "login", sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishLogin verifies the assertion, updates the sign counter, and issues a
// Qeet session token pair for the authenticated user.
func (s *Service) FinishLogin(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, ip, ua string) (*auth.TokenPair, error) {
	userID, tenantID, err := s.verifyLogin(ctx, sessionID, credential)
	if err != nil {
		s.recordFailure(ctx, userID, tenantID, ip, ua, err)
		return nil, err
	}
	return s.auth.IssuePair(ctx, userID, tenantID, ip, ua, "passkey")
}

// recordFailure records a passkey sign-in refused for its ceremony or
// assertion as a failed sign-in, naming the account when it was identified.
// Errors that aren't a refusal (the store failing) aren't recorded.
func (s *Service) recordFailure(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string, err error) {
	refusal := errs.As(err)
	if refusal == nil || s.auth == nil {
		return
	}
	s.auth.RecordSignInFailure(ctx, auth.SignInFailure{
		TenantID: tenantID, UserID: userID, Method: "passkey", Reason: refusal.Code, IP: ip, UserAgent: ua,
	})
}

// FinishLoginSession verifies the assertion, updates the sign counter, and
// opens a hosted-login SSO session for the authenticated user instead of
// issuing a token pair: it returns the user and the raw cookie value to set.
func (s *Service) FinishLoginSession(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, ip, ua string) (uuid.UUID, string, error) {
	userID, tenantID, err := s.verifyLogin(ctx, sessionID, credential)
	if err != nil {
		s.recordFailure(ctx, userID, tenantID, ip, ua, err)
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
// it returns the account (and its organisation) when the ceremony or the
// assertion identified one.
func (s *Service) verifyLogin(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage) (uuid.UUID, uuid.UUID, error) {
	kind, sessUser, sessionData, err := s.takeSession(ctx, sessionID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrPasskeyAssertionInvalid
	}

	var loginUserID, tenantID uuid.UUID
	var cred *webauthn.Credential
	switch kind {
	case "login":
		if sessUser == nil {
			return uuid.Nil, uuid.Nil, errs.ErrPasskeySessionMismatch
		}
		u, tid, err := s.loadUser(ctx, *sessUser)
		if err != nil {
			return uuid.Nil, uuid.Nil, err
		}
		// The organisation's passkey setting is checked before the assertion
		// is verified.
		if err := s.passkeysAllowed(ctx, tid); err != nil {
			return u.id, tid, err
		}
		cred, err = s.wa.ValidateLogin(u, *sessionData, parsed)
		if err != nil {
			return u.id, tid, errs.ErrPasskeyLoginFailed
		}
		loginUserID, tenantID = u.id, tid
	case "login_discoverable":
		var resolved *webauthnUser
		var resolvedTenant uuid.UUID
		var refused error
		// go-webauthn resolves the user before it checks the signature, so a
		// refusal here means the assertion is never verified.
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			uid, err := uuid.FromBytes(userHandle)
			if err != nil {
				return nil, err
			}
			u, tid, err := s.loadUser(ctx, uid)
			if err != nil {
				return nil, err
			}
			resolved, resolvedTenant = u, tid
			if refused = s.passkeysAllowed(ctx, tid); refused != nil {
				return nil, refused
			}
			return u, nil
		}
		cred, err = s.wa.ValidateDiscoverableLogin(handler, *sessionData, parsed)
		var who, whoTenant uuid.UUID
		if resolved != nil {
			who, whoTenant = resolved.id, resolvedTenant
		}
		if refused != nil {
			return who, whoTenant, refused
		}
		if err != nil || resolved == nil {
			return who, whoTenant, errs.ErrPasskeyLoginFailed
		}
		loginUserID, tenantID = resolved.id, resolvedTenant
	default:
		return uuid.Nil, uuid.Nil, errs.ErrPasskeySessionInvalid
	}

	// Signature-counter clone detection. go-webauthn computes CloneWarning in
	// Authenticator.UpdateCounter when the asserted counter fails to advance,
	// but it deliberately leaves the response to the Relying Party (WebAuthn
	// L2 §6.1.1 step 17). Discarding it made the stored sign_count decorative:
	// a credential whose private key had been extracted could replay a stale
	// counter forever and authenticate indefinitely. Refuse the login instead.
	if cred.Authenticator.CloneWarning {
		slog.Error("passkey signature counter regressed — possible cloned authenticator",
			"user_id", loginUserID,
			"tenant_id", tenantID,
			"credential_id", base64.RawURLEncoding.EncodeToString(cred.ID),
			"asserted_sign_count", cred.Authenticator.SignCount,
		)
		return loginUserID, tenantID, errs.ErrPasskeyCloneDetected
	}
	if err := s.q.UpdatePasskeySignCount(ctx, dbgen.UpdatePasskeySignCountParams{
		SignCount:    int64(cred.Authenticator.SignCount),
		BackupState:  cred.Flags.BackupState,
		CredentialID: cred.ID,
	}); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return loginUserID, tenantID, nil
}

// --- WebAuthn as a second factor ---
//
// BeginMFA / FinishMFA reuse a user's *already-registered* passkey credentials
// as a second factor. Unlike BeginLogin/FinishLogin these are scoped to an
// already-authenticated principal (the caller passes the JWT-resolved userID),
// so they assert the known user's credentials and issue NO token pair — the
// session already exists; this only proves recent possession of the key.

// BeginMFA starts a second-factor assertion ceremony for an authenticated user.
// It errors if the user has no registered credentials, and binds the ceremony
// session to the user via a distinct "mfa" kind so a login session can't be
// replayed here (and vice versa).
func (s *Service) BeginMFA(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialAssertion, error) {
	u, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if len(u.creds) == 0 {
		return uuid.Nil, nil, errs.ErrPasskeyNoCredentials
	}
	options, sessionData, err := s.wa.BeginLogin(u)
	if err != nil {
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
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
func (s *Service) FinishMFA(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	kind, sessUser, sessionData, err := s.takeSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if kind != "mfa" || sessUser == nil || *sessUser != userID {
		return errs.ErrPasskeySessionMismatch
	}
	u, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return errs.ErrPasskeyAssertionInvalid
	}
	cred, err := s.wa.ValidateLogin(u, *sessionData, parsed)
	if err != nil {
		return errs.ErrPasskeyMFAFailed
	}
	// See FinishLogin: a counter that fails to advance signals a cloned
	// credential, and a second factor is exactly where that must not pass.
	if cred.Authenticator.CloneWarning {
		slog.Error("passkey signature counter regressed during MFA — possible cloned authenticator",
			"user_id", userID,
			"credential_id", base64.RawURLEncoding.EncodeToString(cred.ID),
			"asserted_sign_count", cred.Authenticator.SignCount,
		)
		return errs.ErrPasskeyCloneDetected
	}
	if err := s.q.UpdatePasskeySignCount(ctx, dbgen.UpdatePasskeySignCountParams{
		SignCount:    int64(cred.Authenticator.SignCount),
		BackupState:  cred.Flags.BackupState,
		CredentialID: cred.ID,
	}); err != nil {
		return err
	}
	return nil
}

// --- HTTP ---

type Handler struct {
	Service *Service
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only); set
	// from SERVICE_ENV != "dev".
	CookieSecure bool
}

// Mount mounts the signed-in passkey routes. The hosted login calls list,
// rename and the two enrolment steps with its session cookie rather than a
// bearer token (see the router's hosted-login session routes); removal stays
// bearer-only.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/passkeys", h.list)
	r.Patch("/passkeys/{id}", h.rename)
	r.Delete("/passkeys/{id}", h.delete)
	r.Post("/passkeys/register/begin", h.registerBegin)
	r.Post("/passkeys/register/finish", h.registerFinish)
}

// MountPublic mounts the passwordless login and signup ceremonies (no JWT —
// the caller isn't authenticated yet).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/passkeys/login/begin", h.loginBegin)
	r.Post("/passkeys/login/finish", h.loginFinish)
	r.Post("/passkeys/login/session", h.loginSession)
	r.Post("/signup/passkey/begin", h.signupBegin)
	r.Post("/signup/passkey/finish", h.signupFinish)
	r.Post("/register/passkey/begin", h.tenantSignupBegin)
	r.Post("/register/passkey/finish", h.tenantSignupFinish)
	r.Post("/invites/accept/passkey/begin", h.inviteSignupBegin)
	r.Post("/invites/accept/passkey/finish", h.inviteSignupFinish)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.List(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// enrollment_allowed tells a UI whether to offer adding a passkey.
	allowed, err := h.Service.EnrolmentAllowed(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "enrollment_allowed": allowed})
}

type renameInput struct {
	Name string `json:"name"`
}

// rename sets the name of one of the caller's own passkeys and returns it.
func (h *Handler) rename(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in renameInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cred, err := h.Service.Rename(r.Context(), id, userID, in.Name)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cred)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	by := user.Remover{UserID: &userID, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if err := h.Service.Delete(r.Context(), id, userID, by); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) registerBegin(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sessionID, options, err := h.Service.BeginRegister(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type registerFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (h *Handler) registerFinish(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in registerFinishInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.FinishRegister(r.Context(), userID, in.SessionID, in.Credential, in.Name, r.UserAgent()); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type loginBeginInput struct {
	Email string `json:"email"`
}

// binding ties a passkey sign-in to the browser that began it: only that
// browser can finish it at the hosted form (loginSession).
func (h *Handler) binding() httpx.BindingCookie {
	return httpx.BindingCookie{Name: "qe_passkey", Secure: h.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: sessionTTL}
}

func (h *Handler) loginBegin(w http.ResponseWriter, r *http.Request) {
	var in loginBeginInput
	// Body is optional: an empty body means discoverable (usernameless) login.
	if r.ContentLength != 0 {
		if err := httpx.DecodeStrictJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	sessionID, options, err := h.Service.BeginLogin(r.Context(), in.Email)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.binding().Add(w, r, sessionID.String())
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type loginFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

// loginFinish is the token form of passkey sign-in: it answers with the token
// pair and sets no cookie, for a caller that keeps tokens on a server (the
// console's). It skips the cross-site check because it bootstraps a bearer
// token, and setting no cookie keeps that true. A browser signs in to the
// hosted login with loginSession instead, so no token pair reaches its script.
func (h *Handler) loginFinish(w http.ResponseWriter, r *http.Request) {
	var in loginFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.FinishLogin(r.Context(), in.SessionID, in.Credential, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

// loginSession is the hosted form of passkey sign-in: it sets the hosted-login
// SSO cookie, so a passkey sign-in can drive the OAuth authorize flow, and
// answers with the user id only — no token reaches the page's script. Only the
// browser that began the ceremony finishes it here; the ceremony is left
// untouched for any other.
func (h *Handler) loginSession(w http.ResponseWriter, r *http.Request) {
	var in loginFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ceremony := in.SessionID.String()
	if !h.binding().Holds(r, ceremony) {
		httpx.WriteError(w, r, errs.ErrPasskeyBrowserMismatch)
		return
	}
	userID, raw, err := h.Service.FinishLoginSession(r.Context(), in.SessionID, in.Credential, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.binding().Remove(w, r, ceremony)
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": userID})
}

type signupBeginInput struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// signupBegin starts a tenant-less passkey-first signup (the passwordless
// counterpart to POST /auth/signup). Enumeration-safe via the same 250ms
// timing floor + neutral-conflict pattern as the password signup endpoints.
func (h *Handler) signupBegin(w http.ResponseWriter, r *http.Request) {
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in signupBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sessionID, options, err := h.Service.BeginSignup(r.Context(), in.Email, in.DisplayName)
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type signupFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (h *Handler) signupFinish(w http.ResponseWriter, r *http.Request) {
	var in signupFinishInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, userID, err := h.Service.FinishSignup(r.Context(), in.SessionID, in.Credential, in.Name, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"user_id":       userID,
		"access_token":  pair.AccessToken,
		"token_type":    pair.TokenType,
		"expires_at":    pair.ExpiresAt,
		"refresh_token": pair.RefreshToken,
		"session_id":    pair.SessionID,
	})
}

type tenantSignupBeginInput struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
}

// tenantSignupBegin starts a tenant-scoped passkey-first signup — the
// passwordless counterpart to POST /auth/register (hosted self-registration).
func (h *Handler) tenantSignupBegin(w http.ResponseWriter, r *http.Request) {
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in tenantSignupBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.TenantID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}
	sessionID, options, err := h.Service.BeginTenantSignup(r.Context(), in.TenantID, in.Email, in.DisplayName)
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

func (h *Handler) tenantSignupFinish(w http.ResponseWriter, r *http.Request) {
	var in signupFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, raw, err := h.Service.FinishTenantSignup(r.Context(), in.SessionID, in.Credential, in.Name, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user_id": userID})
}

// writeSignupError neutralises an email-conflict into the same generic 422
// the password signup endpoints use, so the response can't be used to probe
// whether an email is already registered.
func writeSignupError(w http.ResponseWriter, r *http.Request, err error) {
	if e := errs.As(err); e != nil && e.Code == errs.ErrConflict.Code {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithMessage(
			"We couldn't complete your signup. If you already have an account, try signing in or resetting your password."))
		return
	}
	httpx.WriteError(w, r, err)
}
