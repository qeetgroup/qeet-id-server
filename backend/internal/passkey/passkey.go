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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/pgxerr"
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
	options, sessionData, err := s.wa.BeginRegistration(u)
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

// MountPublic mounts the passwordless login ceremony (no JWT — the user isn't
// authenticated yet).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/passkeys/login/begin", h.loginBegin)
	r.Post("/passkeys/login/finish", h.loginFinish)
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
