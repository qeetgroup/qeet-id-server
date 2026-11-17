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
	"fmt"
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

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkeys/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

const sessionTTL = 5 * time.Minute

// Credential is one of a person's registered passkeys.
type Credential struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       *string    `json:"name"`
	Transports []string   `json:"transports"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Service runs passkey ceremonies and manages stored passkeys. policy says
// whether an organization permits passkeys (nil: no restriction); invitations
// lets an invited person found an account on a passkey (nil: that path is off);
// sender emails the account holder when one is added or removed (nil: no one);
// capture refuses passkey sign-in and sign-up to an address whose organization
// requires single sign-on (nil: none is refused).
type Service struct {
	pool        *pgxpool.Pool
	q           *dbgen.Queries
	wa          *webauthn.WebAuthn
	auth        *auth.Service
	policy      MethodPolicy
	invitations InvitationAcceptor
	sender      notifier.Sender
	capture     auth.DomainCapture
}

// NewService returns the passkey service.
func NewService(pool *pgxpool.Pool, wa *webauthn.WebAuthn, authSvc *auth.Service) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), wa: wa, auth: authSvc}
}

// SetSender sets how the account holder is emailed when a passkey is added to
// or removed from their account.
func (s *Service) SetSender(sender notifier.Sender) { s.sender = sender }

// MethodPolicy says whether an organization permits passkeys. It is satisfied
// by *authpolicy.Service without this package importing it.
type MethodPolicy interface {
	PasskeyEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
}

// SetMethodPolicy wires the organization's passkey on/off setting.
func (s *Service) SetMethodPolicy(p MethodPolicy) { s.policy = p }

// SetDomainCapture wires domain capture into passkey sign-in and sign-up.
func (s *Service) SetDomainCapture(c auth.DomainCapture) { s.capture = c }

// refuseCaptured returns errs.ErrAuthSSORequired when email's domain is
// captured.
func (s *Service) refuseCaptured(ctx context.Context, email string) error {
	if s.capture == nil {
		return nil
	}
	return s.capture.RefuseCaptured(ctx, email)
}

// passkeysAllowed returns ErrPasskeyDisabled if organizationID's policy switches
// passkeys off. uuid.Nil (a user without an organization) is not restricted.
func (s *Service) passkeysAllowed(ctx context.Context, organizationID uuid.UUID) error {
	if organizationID == uuid.Nil || s.policy == nil {
		return nil
	}
	enabled, err := s.policy.PasskeyEnabled(ctx, organizationID)
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
	var organizationID uuid.UUID
	if row.OrganizationID.Valid {
		organizationID = uuid.UUID(row.OrganizationID.Bytes)
	}
	err = s.passkeysAllowed(ctx, organizationID)
	if errors.Is(err, errs.ErrPasskeyDisabled) {
		return false, nil
	}
	return err == nil, err
}

// List returns the user's passkeys.
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

// Requester is who changes a passkey, for its audit record: the account
// holder's request, and the organization their session is in (nil: none).
type Requester struct {
	Actor          audit.Actor
	OrganizationID *uuid.UUID
}

// event returns the audit event of action on userID's account.
func (r Requester) event(action string, userID uuid.UUID, metadata map[string]any) audit.Event {
	e := r.Actor.PlatformEvent(action, "user", userID, metadata)
	e.OrganizationID = r.OrganizationID
	return e
}

// requesterOf is the signed-in caller of r.
func requesterOf(r *http.Request) Requester {
	who := Requester{Actor: audit.ActorOf(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.OrganizationID != nil && *p.OrganizationID != uuid.Nil {
		who.OrganizationID = p.OrganizationID
	}
	return who
}

// Rename sets the name of one of the user's passkeys, recorded as who's. The
// name is cleaned and checked (see validName). Like Delete it is scoped to the
// owner: another user's passkey is not found, and is left unchanged.
func (s *Service) Rename(ctx context.Context, id, userID uuid.UUID, name string, who Requester) (*Credential, error) {
	name, err := validName(name)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	previous, err := q.LockPasskeyCredentialName(ctx, dbgen.LockPasskeyCredentialNameParams{ID: id, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	row, err := q.RenamePasskeyCredential(ctx, dbgen.RenamePasskeyCredentialParams{
		Name:   &name,
		ID:     id,
		UserID: userID,
	})
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, who.event("passkey.renamed", userID,
		map[string]any{"passkey_id": id, "name": name, "previous_name": nameOf(previous)})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	c := credentialFromRow(dbgen.ListPasskeyCredentialsRow(row))
	return &c, nil
}

// Delete removes one of the user's own passkeys, recorded as who's, and tells
// the account holder. Another user's passkey is ErrNotFound and nothing is
// deleted; removing the account's only way to sign in is refused with
// ErrAuthLastSignInMethod, and the refusal recorded.
func (s *Service) Delete(ctx context.Context, id, userID uuid.UUID, who Requester) error {
	// The account's other ways to sign in span its organizations.
	ctx = postgres.AcrossOrganizations(ctx)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, userID)
	if err != nil {
		return err
	}
	name, err := s.q.WithTx(tx).DeletePasskeyCredential(ctx, dbgen.DeletePasskeyCredentialParams{
		ID:     id,
		UserID: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		by := user.Remover{UserID: who.Actor.UserID, IP: who.Actor.IP, UserAgent: who.Actor.UserAgent, RequestID: who.Actor.RequestID}
		return user.RefuseLastMethodRemoval(ctx, s.pool, userID, who.OrganizationID, "passkey", id, by)
	}
	if err := audit.Record(ctx, tx, who.event("passkey.deleted", userID,
		map[string]any{"passkey_id": id, "name": nameOf(name)})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.tellPasskeyChange(ctx, userID, passkeyRemoved, nameOf(name))
	return nil
}

// nameOf is a stored passkey name, "" for none.
func nameOf(name *string) string {
	if name == nil {
		return ""
	}
	return *name
}

// passkeyChange is what happened to one of a person's passkeys.
type passkeyChange int

const (
	passkeyAdded passkeyChange = iota
	passkeyRemoved
)

// tellPasskeyChange emails the account holder that a passkey was added to or
// removed from their account, so one they didn't add is noticed. Best effort,
// after the change has committed: a failure is logged, the change stands.
func (s *Service) tellPasskeyChange(ctx context.Context, userID uuid.UUID, change passkeyChange, name string) {
	if s.sender == nil {
		return
	}
	account, err := s.q.GetUserForWebAuthn(ctx, userID)
	if err != nil || account.Email == "" {
		slog.Warn("passkey change notice not sent: no address", "err", err, "user_id", userID)
		return
	}
	subject, intro := "A passkey was added to your account",
		fmt.Sprintf("A passkey named “%s” was added to your Qeet ID account and can now be used to sign in.", name)
	note := "If you didn't add it, remove it from your account's security settings and contact your organization's administrator right away."
	if change == passkeyRemoved {
		subject, intro = "A passkey was removed from your account",
			fmt.Sprintf("The passkey named “%s” was removed from your Qeet ID account and can no longer be used to sign in.", name)
		note = "If you didn't remove it, contact your organization's administrator right away."
	}
	msg := notifier.Message{Channel: "email", To: account.Email, Subject: subject, Body: intro + " " + note, HTML: emailtmpl.Notice(subject, intro, note)}
	if account.OrganizationID.Valid {
		msg.OrganizationID = uuid.UUID(account.OrganizationID.Bytes).String()
	}
	if err := s.sender.Send(ctx, msg); err != nil {
		slog.Warn("passkey change notice not sent", "err", err, "user_id", userID)
	}
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

// loadUser builds a webauthnUser (with stored credentials), read through q,
// and returns the user's organization id (uuid.Nil when organization-less).
func loadUser(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) (*webauthnUser, uuid.UUID, error) {
	row, err := q.GetUserForWebAuthn(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, errs.ErrPasskeyUserNotFound
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
	if row.OrganizationID.Valid {
		tid = uuid.UUID(row.OrganizationID.Bytes)
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

// takeSession reads and deletes a ceremony session (single-use) through q.
func takeSession(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (kind string, userID *uuid.UUID, data *webauthn.SessionData, err error) {
	row, err := q.TakeWebAuthnSession(ctx, id)
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
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
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
	name, err := enrolmentName(name, who.Actor.UserAgent)
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
	return s.insertCredential(ctx, userID, cred, name, who)
}

// insertCredential stores a verified credential for userID with its audit
// record, then tells the account holder.
func (s *Service) insertCredential(ctx context.Context, userID uuid.UUID, cred *webauthn.Credential, name string, who Requester) error {
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
		if pgxerr.IsUnique(err) {
			return errs.ErrPasskeyExists
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
	organizationPG := pgtype.UUID{}
	if organizationID != uuid.Nil {
		organizationPG = pgtype.UUID{Bytes: organizationID, Valid: true}
	}
	return s.q.InsertSignupWebAuthnSession(ctx, dbgen.InsertSignupWebAuthnSessionParams{
		Data:                  raw,
		ExpiresAt:             time.Now().UTC().Add(sessionTTL),
		SubjectID:             pgtype.UUID{Bytes: subjectID, Valid: true},
		PendingEmail:          &email,
		PendingDisplayName:    dnPtr,
		PendingOrganizationID: organizationPG,
		InviteID:              pgtype.UUID{Bytes: inviteID, Valid: inviteID != uuid.Nil},
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
	if row.PendingOrganizationID.Valid {
		sess.organizationID = uuid.UUID(row.PendingOrganizationID.Bytes)
	}
	if row.PendingInviteID.Valid {
		sess.inviteID = uuid.UUID(row.PendingInviteID.Bytes)
	}
	return sess, nil
}

// BeginSignup starts a passkey-founded registration ceremony for a brand-new,
// organization-less account — the passwordless counterpart to auth.Service.Signup.
func (s *Service) BeginSignup(ctx context.Context, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	return s.beginSignup(ctx, uuid.Nil, email, displayName)
}

// BeginOrganizationSignup starts the same ceremony for an organization's hosted signup, the
// passwordless auth.Service.RegisterInOrganization. It is refused unless the organization
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
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
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
// of a token pair, as auth.Service.RegisterInOrganization does.
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
		return uuid.Nil, "", errs.ErrPasskeySessionInvalid
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

	organizationPG := pgtype.UUID{}
	if sess.organizationID != uuid.Nil {
		organizationPG = pgtype.UUID{Bytes: sess.organizationID, Valid: true}
	}
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

// BeginLogin starts a login ceremony. Every ceremony is discoverable, so the
// answer is the same whether or not email has an account or a passkey; with an
// email, only a passkey of that account can finish it. An email whose
// organization requires single sign-on is refused before it is looked up; a
// passkey of such an account is refused when it finishes (verifyLogin).
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
		return uuid.Nil, nil, errs.ErrPasskeyCeremonyFailed.Wrap(err)
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
	if refusal == nil || s.auth == nil {
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
		return uuid.Nil, uuid.Nil, errs.ErrPasskeyAssertionInvalid
	}

	if kind != "login" && kind != "login_discoverable" {
		return uuid.Nil, uuid.Nil, errs.ErrPasskeySessionInvalid
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
			return nil, errs.ErrPasskeyLoginFailed
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
		return who, whoOrganization, errs.ErrPasskeyLoginFailed
	}
	loginUserID, organizationID := resolved.id, resolvedOrganization

	// A sign counter that failed to advance may mean a cloned authenticator.
	// go-webauthn flags it and leaves the response to the RP (WebAuthn L2 §6.1.1
	// step 17); refuse, or a copied key could keep signing in.
	if cred.Authenticator.CloneWarning {
		slog.Error("passkey signature counter regressed — possible cloned authenticator",
			"user_id", loginUserID,
			"tenant_id", organizationID,
			"credential_id", base64.RawURLEncoding.EncodeToString(cred.ID),
			"asserted_sign_count", cred.Authenticator.SignCount,
		)
		return loginUserID, organizationID, errs.ErrPasskeyCloneDetected
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

// --- WebAuthn as a second factor ---
//
// BeginMFA and FinishMFA assert a signed-in user's existing passkeys to prove
// recent possession of one. Unlike sign-in, they issue no tokens.

// BeginMFA starts a second-factor assertion ceremony for an authenticated user.
// It errors if the user has no registered credentials, and binds the ceremony
// session to the user via a distinct "mfa" kind so a login session can't be
// replayed here (and vice versa).
func (s *Service) BeginMFA(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialAssertion, error) {
	u, _, err := loadUser(ctx, s.q, userID)
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
	return s.finishMFA(ctx, s.q, userID, sessionID, credential)
}

// FinishMFATx is FinishMFA inside the caller's transaction: the ceremony
// session is taken, the user loaded and the sign counter updated through tx.
func (s *Service) FinishMFATx(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	return s.finishMFA(ctx, s.q.WithTx(tx), userID, sessionID, credential)
}

func (s *Service) finishMFA(ctx context.Context, q *dbgen.Queries, userID, sessionID uuid.UUID, credential json.RawMessage) error {
	kind, sessUser, sessionData, err := takeSession(ctx, q, sessionID)
	if err != nil {
		return err
	}
	if kind != "mfa" || sessUser == nil || *sessUser != userID {
		return errs.ErrPasskeySessionMismatch
	}
	u, _, err := loadUser(ctx, q, userID)
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
	// See verifyLogin: a counter that fails to advance signals a cloned
	// credential, and a second factor is exactly where that must not pass.
	if cred.Authenticator.CloneWarning {
		slog.Error("passkey signature counter regressed during MFA — possible cloned authenticator",
			"user_id", userID,
			"credential_id", base64.RawURLEncoding.EncodeToString(cred.ID),
			"asserted_sign_count", cred.Authenticator.SignCount,
		)
		return errs.ErrPasskeyCloneDetected
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

// --- HTTP ---

// Handler serves the passkey routes. CookieSecure marks the hosted-login SSO
// cookie Secure (HTTPS-only).
type Handler struct {
	Service      *Service
	CookieSecure bool
}

// Mount mounts the signed-in passkey routes. The hosted login calls each of
// them (list, rename, remove and the two enrolment steps) with its session
// cookie rather than a bearer token (see the router's hosted-login session
// routes).
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
	r.Post("/register/passkey/begin", h.organizationSignupBegin)
	r.Post("/register/passkey/finish", h.organizationSignupFinish)
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
	httpx.WriteJSON(w, http.StatusOK, paging.ListWith(out, map[string]any{"enrollment_allowed": allowed}))
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
	cred, err := h.Service.Rename(r.Context(), id, userID, in.Name, requesterOf(r))
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
	if err := h.Service.Delete(r.Context(), id, userID, requesterOf(r)); err != nil {
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
	if err := h.Service.FinishRegister(r.Context(), userID, in.SessionID, in.Credential, in.Name, requesterOf(r)); err != nil {
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

// loginFinish is the token form of passkey sign-in, for a server-side caller
// such as the console: it returns the token pair and sets no cookie, which is
// why it may skip the cross-site check. A browser on the hosted login uses
// loginSession instead, so no token pair reaches a page's script.
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
// SSO cookie, so the sign-in can drive the OAuth authorize flow, and returns
// only the user id. Only the browser that began the ceremony can finish it
// here; for any other the ceremony is left untouched.
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

// signupBegin starts an organization-less passkey-first signup, the passwordless
// POST /auth/signup. Like the password endpoints it answers no sooner than
// 250ms and reports errors through writeSignupError.
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

type organizationSignupBeginInput struct {
	OrganizationID uuid.UUID `json:"tenant_id"`
	Email          string    `json:"email"`
	DisplayName    string    `json:"display_name"`
}

// organizationSignupBegin starts an organization-scoped passkey-first signup — the
// passwordless counterpart to POST /auth/register (hosted self-registration).
func (h *Handler) organizationSignupBegin(w http.ResponseWriter, r *http.Request) {
	const signupFloor = 250 * time.Millisecond
	start := time.Now()
	defer httpx.ConstantTimeFloor(r.Context(), start, signupFloor)

	var in organizationSignupBeginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.OrganizationID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}
	sessionID, options, err := h.Service.BeginOrganizationSignup(r.Context(), in.OrganizationID, in.Email, in.DisplayName)
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

func (h *Handler) organizationSignupFinish(w http.ResponseWriter, r *http.Request) {
	var in signupFinishInput
	if err := httpx.DecodeStrictJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, raw, err := h.Service.FinishOrganizationSignup(r.Context(), in.SessionID, in.Credential, in.Name, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		writeSignupError(w, r, err)
		return
	}
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user_id": userID})
}

// writeSignupError answers an email that already has an account with the
// neutral 422 the password sign-up endpoints use (auth.NeutralSignupError), so
// the answer can't reveal whether an email is registered.
func writeSignupError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.WriteError(w, r, auth.NeutralSignupError(err))
}
