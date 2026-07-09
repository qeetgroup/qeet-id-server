// Package passkey implements WebAuthn passkey registration and login on top of
// go-webauthn. The credential store (auth.passkey_credentials) backs list/delete
// and the ceremony; in-flight challenges live in auth.webauthn_sessions.
package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
	"github.com/qeetgroup/qeet-id/platform/database/postgres/pgxerr"
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
	wa   *webauthn.WebAuthn
	auth *auth.Service
}

func NewService(pool *pgxpool.Pool, wa *webauthn.WebAuthn, authSvc *auth.Service) *Service {
	return &Service{pool: pool, wa: wa, auth: authSvc}
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, transports, last_used_at, created_at
		FROM auth.passkey_credentials WHERE user_id = $1 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.UserID, &c.Name, &c.Transports, &c.LastUsedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Delete is scoped to the owner so one user can't delete another's passkey.
func (s *Service) Delete(ctx context.Context, id, userID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM auth.passkey_credentials WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
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
	var email string
	var displayName *string
	var tenantID *uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT email, display_name, tenant_id FROM "user".users
		WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(&email, &displayName, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, errs.ErrNotFound.WithDetail("user not found")
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	creds, err := s.loadCredentials(ctx, userID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	dn := email
	if displayName != nil && *displayName != "" {
		dn = *displayName
	}
	var tid uuid.UUID
	if tenantID != nil {
		tid = *tenantID
	}
	return &webauthnUser{id: userID, name: email, displayName: dn, creds: creds}, tid, nil
}

func (s *Service) loadUserByEmail(ctx context.Context, email string) (*webauthnUser, uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`, email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, errs.ErrNotFound.WithDetail("user not found")
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	return s.loadUser(ctx, id)
}

func (s *Service) loadCredentials(ctx context.Context, userID uuid.UUID) ([]webauthn.Credential, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT credential_id, public_key, sign_count, aaguid, transports
		FROM auth.passkey_credentials WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var (
			credID     []byte
			pubKey     []byte
			signCount  int64
			aaguid     *uuid.UUID
			transports []string
		)
		if err := rows.Scan(&credID, &pubKey, &signCount, &aaguid, &transports); err != nil {
			return nil, err
		}
		c := webauthn.Credential{ID: credID, PublicKey: pubKey}
		c.Authenticator.SignCount = uint32(signCount)
		if aaguid != nil {
			b := *aaguid
			c.Authenticator.AAGUID = b[:]
		}
		for _, t := range transports {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// storeSession persists in-flight ceremony state and returns its opaque id.
func (s *Service) storeSession(ctx context.Context, userID *uuid.UUID, kind string, data *webauthn.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.webauthn_sessions (user_id, kind, data, expires_at)
		VALUES ($1, $2, $3, $4) RETURNING id
	`, userID, kind, raw, time.Now().UTC().Add(sessionTTL)).Scan(&id)
	return id, err
}

// takeSession reads and deletes a ceremony session (single-use).
func (s *Service) takeSession(ctx context.Context, id uuid.UUID) (kind string, userID *uuid.UUID, data *webauthn.SessionData, err error) {
	var raw []byte
	var expiresAt time.Time
	err = s.pool.QueryRow(ctx, `
		DELETE FROM auth.webauthn_sessions WHERE id = $1
		RETURNING kind, user_id, data, expires_at
	`, id).Scan(&kind, &userID, &raw, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil, errs.ErrBadRequest.WithDetail("invalid or used session")
	}
	if err != nil {
		return "", nil, nil, err
	}
	if time.Now().After(expiresAt) {
		return "", nil, nil, errs.ErrBadRequest.WithDetail("session expired")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(raw, &sd); err != nil {
		return "", nil, nil, err
	}
	return kind, userID, &sd, nil
}

// BeginRegister starts a registration ceremony for an authenticated user.
func (s *Service) BeginRegister(ctx context.Context, userID uuid.UUID) (uuid.UUID, *protocol.CredentialCreation, error) {
	u, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	// Require a discoverable (resident) credential so the passwordless,
	// usernameless login flow (BeginDiscoverableLogin) can find it — passkeys
	// registered without this aren't discoverable and break login on the hosted
	// app. UV is "preferred" to keep hardware keys without a PIN usable.
	options, sessionData, err := s.wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return uuid.Nil, nil, errs.ErrBadRequest.WithDetail(err.Error())
	}
	id, err := s.storeSession(ctx, &userID, "register", sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishRegister verifies the attestation and persists the new credential.
func (s *Service) FinishRegister(ctx context.Context, userID, sessionID uuid.UUID, credential json.RawMessage, name string) error {
	kind, sessUser, sessionData, err := s.takeSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if kind != "register" || sessUser == nil || *sessUser != userID {
		return errs.ErrBadRequest.WithDetail("session mismatch")
	}
	u, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credential))
	if err != nil {
		return errs.ErrBadRequest.WithDetail("invalid attestation")
	}
	cred, err := s.wa.CreateCredential(u, *sessionData, parsed)
	if err != nil {
		return errs.ErrBadRequest.WithDetail(err.Error())
	}
	return s.insertCredential(ctx, userID, cred, name)
}

func (s *Service) insertCredential(ctx context.Context, userID uuid.UUID, cred *webauthn.Credential, name string) error {
	var aaguid *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if g, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil && g != uuid.Nil {
			aaguid = &g
		}
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	var namePtr any
	if name != "" {
		namePtr = name
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, aaguid, transports, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, userID, cred.ID, cred.PublicKey, int64(cred.Authenticator.SignCount), aaguid, transports, namePtr)
	if err != nil {
		if pgxerr.IsUnique(err) {
			return errs.ErrConflict.WithDetail("passkey already registered")
		}
		return err
	}
	return nil
}

// --- Passkey-first signup (no existing user/password required) ---
//
// BeginSignup/FinishSignup and BeginTenantSignup/FinishTenantSignup let a
// brand-new account be founded on a passkey instead of a password. Since no
// user row exists yet at Begin time, the ceremony carries an ephemeral
// "subject" WebAuthn ID plus the pending account details in
// auth.webauthn_sessions (subject_id/pending_*) rather than a real user_id —
// the real user row (and its passkey credential) is only created once
// FinishSignup verifies the attestation.

// signupSession is a decoded pending-signup ceremony.
type signupSession struct {
	subjectID   uuid.UUID
	email       string
	displayName string
	tenantID    uuid.UUID
	data        *webauthn.SessionData
}

// storeSignupSession persists an in-flight pre-account registration ceremony.
// tenantID is uuid.Nil for a tenant-less (direct) signup.
func (s *Service) storeSignupSession(ctx context.Context, subjectID uuid.UUID, email, displayName string, tenantID uuid.UUID, data *webauthn.SessionData) (uuid.UUID, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return uuid.Nil, err
	}
	var tenantArg any
	if tenantID != uuid.Nil {
		tenantArg = tenantID
	}
	var dnArg any
	if displayName != "" {
		dnArg = displayName
	}
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.webauthn_sessions (kind, data, expires_at, subject_id, pending_email, pending_display_name, pending_tenant_id)
		VALUES ('signup', $1, $2, $3, $4, $5, $6) RETURNING id
	`, raw, time.Now().UTC().Add(sessionTTL), subjectID, email, dnArg, tenantArg).Scan(&id)
	return id, err
}

// takeSignupSession reads and deletes a pending-signup ceremony (single-use).
func (s *Service) takeSignupSession(ctx context.Context, id uuid.UUID) (*signupSession, error) {
	var raw []byte
	var expiresAt time.Time
	var kind string
	var subjectID *uuid.UUID
	var email, displayName *string
	var tenantID *uuid.UUID
	err := s.pool.QueryRow(ctx, `
		DELETE FROM auth.webauthn_sessions WHERE id = $1
		RETURNING kind, data, expires_at, subject_id, pending_email, pending_display_name, pending_tenant_id
	`, id).Scan(&kind, &raw, &expiresAt, &subjectID, &email, &displayName, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("invalid or used session")
	}
	if err != nil {
		return nil, err
	}
	if kind != "signup" || subjectID == nil || email == nil {
		return nil, errs.ErrBadRequest.WithDetail("not a signup session")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("session expired")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(raw, &sd); err != nil {
		return nil, err
	}
	sess := &signupSession{subjectID: *subjectID, email: *email, data: &sd}
	if displayName != nil {
		sess.displayName = *displayName
	}
	if tenantID != nil {
		sess.tenantID = *tenantID
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
// Gated by the same self_registration_enabled policy.
func (s *Service) BeginTenantSignup(ctx context.Context, tenantID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	enabled, err := s.auth.SelfRegistrationEnabled(ctx, tenantID)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if !enabled {
		return uuid.Nil, nil, errs.ErrForbidden.
			WithMessage("Self-registration is not enabled for this application.").
			WithDetail("self-registration disabled")
	}
	return s.beginSignup(ctx, tenantID, email, displayName)
}

func (s *Service) beginSignup(ctx context.Context, tenantID uuid.UUID, email, displayName string) (uuid.UUID, *protocol.CredentialCreation, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return uuid.Nil, nil, errs.ErrUnprocessable.WithDetail("email is required")
	}
	var exists bool
	var err error
	if tenantID == uuid.Nil {
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM "user".users WHERE LOWER(email) = LOWER($1) AND tenant_id IS NULL AND deleted_at IS NULL)
		`, email).Scan(&exists)
	} else {
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM "user".users WHERE LOWER(email) = LOWER($1) AND tenant_id = $2 AND deleted_at IS NULL)
		`, email, tenantID).Scan(&exists)
	}
	if err != nil {
		return uuid.Nil, nil, err
	}
	if exists {
		return uuid.Nil, nil, errs.ErrConflict.WithDetail("email already exists")
	}

	// subjectID only correlates this ceremony's challenge with its attestation
	// response — it is never written to user_id (no row exists yet) and is
	// discarded once the real user is created in finishSignup.
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
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return uuid.Nil, nil, errs.ErrBadRequest.WithDetail(err.Error())
	}
	id, err := s.storeSignupSession(ctx, subjectID, email, displayName, tenantID, sessionData)
	if err != nil {
		return uuid.Nil, nil, err
	}
	return id, options, nil
}

// FinishSignup verifies the attestation, creates the tenant-less user with the
// passkey as its founding credential (no password), and signs them in.
func (s *Service) FinishSignup(ctx context.Context, sessionID uuid.UUID, credential json.RawMessage, name, ip, ua string) (*auth.TokenPair, uuid.UUID, error) {
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return nil, uuid.Nil, err
	}
	userID, err := s.createUserFromSignup(ctx, sess, cred, name)
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
	sess, cred, err := s.verifySignupAttestation(ctx, sessionID, credential)
	if err != nil {
		return uuid.Nil, "", err
	}
	if sess.tenantID == uuid.Nil {
		return uuid.Nil, "", errs.ErrBadRequest.WithDetail("not a tenant signup session")
	}
	userID, err := s.createUserFromSignup(ctx, sess, cred, name)
	if err != nil {
		return uuid.Nil, "", err
	}
	raw, err := s.auth.CreateLoginSession(ctx, userID, ip, ua)
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
		return nil, nil, errs.ErrBadRequest.WithDetail("invalid attestation")
	}
	cred, err := s.wa.CreateCredential(u, *sess.data, parsed)
	if err != nil {
		return nil, nil, errs.ErrBadRequest.WithDetail(err.Error())
	}
	return sess, cred, nil
}

// createUserFromSignup inserts the user row (no password credential) and
// attaches the verified passkey as its founding credential, atomically.
func (s *Service) createUserFromSignup(ctx context.Context, sess *signupSession, cred *webauthn.Credential, name string) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var tenantArg, dnArg any
	if sess.tenantID != uuid.Nil {
		tenantArg = sess.tenantID
	}
	if sess.displayName != "" {
		dnArg = sess.displayName
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, display_name)
		VALUES ($1, $2, $3)
		RETURNING id
	`, tenantArg, sess.email, dnArg).Scan(&userID)
	if err != nil {
		if pgxerr.IsUnique(err) {
			return uuid.Nil, errs.ErrConflict.WithDetail("email already exists")
		}
		return uuid.Nil, err
	}

	var aaguid *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if g, gerr := uuid.FromBytes(cred.Authenticator.AAGUID); gerr == nil && g != uuid.Nil {
			aaguid = &g
		}
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	var namePtr any
	if name != "" {
		namePtr = name
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, aaguid, transports, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, userID, cred.ID, cred.PublicKey, int64(cred.Authenticator.SignCount), aaguid, transports, namePtr); err != nil {
		if pgxerr.IsUnique(err) {
			return uuid.Nil, errs.ErrConflict.WithDetail("passkey already registered")
		}
		return uuid.Nil, err
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
			return uuid.Nil, nil, errs.ErrBadRequest.WithDetail(err.Error())
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
		return uuid.Nil, nil, errs.ErrBadRequest.WithDetail("no passkeys for user")
	}
	options, sessionData, err := s.wa.BeginLogin(u)
	if err != nil {
		return uuid.Nil, nil, errs.ErrBadRequest.WithDetail(err.Error())
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
	kind, sessUser, sessionData, err := s.takeSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return nil, errs.ErrBadRequest.WithDetail("invalid assertion")
	}

	var loginUserID, tenantID uuid.UUID
	var cred *webauthn.Credential
	switch kind {
	case "login":
		if sessUser == nil {
			return nil, errs.ErrBadRequest.WithDetail("session mismatch")
		}
		u, tid, err := s.loadUser(ctx, *sessUser)
		if err != nil {
			return nil, err
		}
		cred, err = s.wa.ValidateLogin(u, *sessionData, parsed)
		if err != nil {
			return nil, errs.ErrUnauthorized.WithDetail("login verification failed")
		}
		loginUserID, tenantID = u.id, tid
	case "login_discoverable":
		var resolved *webauthnUser
		var resolvedTenant uuid.UUID
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
			return u, nil
		}
		cred, err = s.wa.ValidateDiscoverableLogin(handler, *sessionData, parsed)
		if err != nil || resolved == nil {
			return nil, errs.ErrUnauthorized.WithDetail("login verification failed")
		}
		loginUserID, tenantID = resolved.id, resolvedTenant
	default:
		return nil, errs.ErrBadRequest.WithDetail("not a login session")
	}

	if _, err := s.pool.Exec(ctx, `
		UPDATE auth.passkey_credentials SET sign_count = $1, last_used_at = NOW()
		WHERE credential_id = $2
	`, int64(cred.Authenticator.SignCount), cred.ID); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, loginUserID, tenantID, ip, ua, "passkey")
}

// StartLoginSession mints a hosted-login SSO session for a freshly-authenticated
// passkey user, so a passkey login can also drive the OAuth authorize/consent
// flow (the cookie is set by the handler).
func (s *Service) StartLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	return s.auth.CreateLoginSession(ctx, userID, ip, ua)
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
		return uuid.Nil, nil, errs.ErrBadRequest.WithDetail("no passkeys for user")
	}
	options, sessionData, err := s.wa.BeginLogin(u)
	if err != nil {
		return uuid.Nil, nil, errs.ErrBadRequest.WithDetail(err.Error())
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
		return errs.ErrBadRequest.WithDetail("session mismatch")
	}
	u, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(credential))
	if err != nil {
		return errs.ErrBadRequest.WithDetail("invalid assertion")
	}
	cred, err := s.wa.ValidateLogin(u, *sessionData, parsed)
	if err != nil {
		return errs.ErrUnauthorized.WithDetail("mfa verification failed")
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE auth.passkey_credentials SET sign_count = $1, last_used_at = NOW()
		WHERE credential_id = $2
	`, int64(cred.Authenticator.SignCount), cred.ID); err != nil {
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

func (h *Handler) Mount(r chi.Router) {
	r.Get("/passkeys", h.list)
	r.Delete("/passkeys/{id}", h.delete)
	r.Post("/passkeys/register/begin", h.registerBegin)
	r.Post("/passkeys/register/finish", h.registerFinish)
}

// MountPublic mounts the passwordless login and signup ceremonies (no JWT —
// the caller isn't authenticated yet).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/passkeys/login/begin", h.loginBegin)
	r.Post("/passkeys/login/finish", h.loginFinish)
	r.Post("/signup/passkey/begin", h.signupBegin)
	r.Post("/signup/passkey/finish", h.signupFinish)
	r.Post("/register/passkey/begin", h.tenantSignupBegin)
	r.Post("/register/passkey/finish", h.tenantSignupFinish)
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
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
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
	if err := h.Service.Delete(r.Context(), id, userID); err != nil {
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
	if err := h.Service.FinishRegister(r.Context(), userID, in.SessionID, in.Credential, in.Name); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type loginBeginInput struct {
	Email string `json:"email"`
}

func (h *Handler) loginBegin(w http.ResponseWriter, r *http.Request) {
	var in loginBeginInput
	// Body is optional: an empty body means discoverable (usernameless) login.
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	sessionID, options, err := h.Service.BeginLogin(r.Context(), in.Email)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"publicKey":  options.Response,
	})
}

type loginFinishInput struct {
	SessionID  uuid.UUID       `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

func (h *Handler) loginFinish(w http.ResponseWriter, r *http.Request) {
	var in loginFinishInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.FinishLogin(r.Context(), in.SessionID, in.Credential, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Also establish the hosted-login SSO cookie so a passkey login can drive
	// the OAuth authorize flow. Best-effort and harmless for the admin SPA,
	// which authenticates with the bearer token and ignores the cookie.
	if raw, serr := h.Service.StartLoginSession(r.Context(), pair.UserID, httpx.ClientIP(r), r.UserAgent()); serr == nil {
		auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
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
	if err := httpx.DecodeJSON(r, &in); err != nil {
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
