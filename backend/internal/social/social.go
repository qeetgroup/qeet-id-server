// Package social manages tenant-configured external identity providers
// (Google, Microsoft, Okta, ...) and the externally-issued identity rows that
// link to a Qeet user. It also drives the OIDC authorization-code login
// ceremony for discovery-based providers (see oauthclient.go).
package social

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Provider struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	DiscoveryURL *string   `json:"discovery_url"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type ExternalIdentity struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Provider string    `json:"provider"`
	Subject  string    `json:"subject"`
	Email    *string   `json:"email"`
	LinkedAt time.Time `json:"linked_at"`
}

type Service struct {
	pool       *pgxpool.Pool
	auth       *auth.Service
	appBaseURL string
	oauth      *oauthClient
}

func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string) *Service {
	return &Service{
		pool:       pool,
		auth:       authSvc,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
		oauth:      newOAuthClient(),
	}
}

type CreateProviderInput struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	DiscoveryURL string    `json:"discovery_url"`
}

func (s *Service) UpsertProvider(ctx context.Context, in CreateProviderInput) (*Provider, error) {
	var p Provider
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
		VALUES ($1, $2, $3, $4, NULLIF($5,''))
		ON CONFLICT (tenant_id, provider) DO UPDATE SET
			client_id = EXCLUDED.client_id,
			client_secret = EXCLUDED.client_secret,
			discovery_url = EXCLUDED.discovery_url,
			enabled = TRUE
		RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at
	`, in.TenantID, in.Provider, in.ClientID, in.ClientSecret, in.DiscoveryURL).
		Scan(&p.ID, &p.TenantID, &p.Provider, &p.ClientID, &p.DiscoveryURL, &p.Enabled, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) ListProviders(ctx context.Context, tenantID uuid.UUID) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, provider, client_id, discovery_url, enabled, created_at
		FROM tenant.social_providers WHERE tenant_id = $1 ORDER BY provider
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Provider, &p.ClientID, &p.DiscoveryURL, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Service) ListIdentities(ctx context.Context, userID, tenantID uuid.UUID) ([]ExternalIdentity, error) {
	// Tenant-scoped so one tenant can't read another's linked identities;
	// the deleted_at join keeps soft-deleted users out of admin lookups.
	rows, err := s.pool.Query(ctx, `
		SELECT ei.id, ei.user_id, ei.tenant_id, ei.provider, ei.subject, ei.email, ei.linked_at
		FROM "user".external_identities ei
		JOIN "user".users u ON u.id = ei.user_id
		WHERE ei.user_id = $1 AND ei.tenant_id = $2 AND u.deleted_at IS NULL
		ORDER BY ei.linked_at DESC
	`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExternalIdentity
	for rows.Next() {
		var e ExternalIdentity
		if err := rows.Scan(&e.ID, &e.UserID, &e.TenantID, &e.Provider, &e.Subject, &e.Email, &e.LinkedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// Unlink is tenant-scoped so an identity can only be removed within its tenant.
func (s *Service) Unlink(ctx context.Context, id, tenantID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM "user".external_identities WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

const (
	socialStateTTL = 10 * time.Minute
	socialCodeTTL  = 2 * time.Minute
	socialScopes   = "openid email profile"
)

// providerConfig is a tenant's stored config for one OIDC provider.
type providerConfig struct {
	clientID     string
	clientSecret string
	discoveryURL string
}

// resolveTenant maps a tenant id (uuid) or slug to a tenant id.
func (s *Service) resolveTenant(ctx context.Context, ref string) (uuid.UUID, error) {
	if ref == "" {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("tenant required")
	}
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT id FROM tenant.tenants WHERE slug = $1`, ref).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrNotFound.WithDetail("unknown tenant")
	}
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// loadProvider returns an enabled, discovery-based provider config for a tenant.
func (s *Service) loadProvider(ctx context.Context, tenantID uuid.UUID, provider string) (providerConfig, error) {
	var pc providerConfig
	var discovery *string
	var enabled bool
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret, discovery_url, enabled
		FROM tenant.social_providers WHERE tenant_id = $1 AND provider = $2
	`, tenantID, provider).Scan(&pc.clientID, &pc.clientSecret, &discovery, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return pc, errs.ErrNotFound.WithDetail("provider not configured")
	}
	if err != nil {
		return pc, err
	}
	if !enabled {
		return pc, errs.ErrBadRequest.WithDetail("provider disabled")
	}
	if discovery == nil || *discovery == "" {
		return pc, errs.ErrBadRequest.WithDetail("provider has no discovery_url (OIDC discovery required)")
	}
	pc.discoveryURL = *discovery
	return pc, nil
}

// BeginLogin resolves the tenant + provider, persists CSRF state with a PKCE
// verifier, and returns the upstream authorization URL to redirect the user to.
func (s *Service) BeginLogin(ctx context.Context, provider, tenantRef, redirectURI, returnTo string) (string, error) {
	tenantID, err := s.resolveTenant(ctx, tenantRef)
	if err != nil {
		return "", err
	}
	pc, err := s.loadProvider(ctx, tenantID, provider)
	if err != nil {
		return "", err
	}
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return "", errs.ErrUnprocessable.WithDetail("provider discovery failed")
	}
	// PKCE S256: verifier is the raw token, challenge is its SHA-256 (codes.Hash).
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	state, stateHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.social_oauth_states (state_hash, tenant_id, provider, code_verifier, redirect_uri, return_to, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, stateHash, tenantID, provider, verifier, redirectURI, returnTo, time.Now().UTC().Add(socialStateTTL)); err != nil {
		return "", err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {pc.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {socialScopes},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(doc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return doc.AuthorizationEndpoint + sep + q.Encode(), nil
}

// CallbackResult is what a successful provider callback yields: a one-time code
// the SPA trades for a session, plus the hosted return_to and the resolved user
// (used by the hosted flow to set an SSO cookie and redirect).
type CallbackResult struct {
	Code     string
	ReturnTo string
	UserID   uuid.UUID
	TenantID uuid.UUID
}

// CompleteCallback consumes the CSRF state, exchanges the code with the upstream
// provider, find-or-creates the local user + external identity, and mints a
// one-time code the SPA trades for a session.
func (s *Service) CompleteCallback(ctx context.Context, provider, state, code string) (*CallbackResult, error) {
	if state == "" || code == "" {
		return nil, errs.ErrBadRequest.WithDetail("missing state or code")
	}
	stateHash := codes.Hash(state)

	var (
		tenantID       uuid.UUID
		dbProvider     string
		verifier       string
		storedRedirect string
		returnTo       string
		expiresAt      time.Time
	)
	// Single-use: delete the state row as we read it.
	err := s.pool.QueryRow(ctx, `
		DELETE FROM auth.social_oauth_states WHERE state_hash = $1
		RETURNING tenant_id, provider, code_verifier, redirect_uri, return_to, expires_at
	`, stateHash).Scan(&tenantID, &dbProvider, &verifier, &storedRedirect, &returnTo, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("invalid or used state")
	}
	if err != nil {
		return nil, err
	}
	if dbProvider != provider {
		return nil, errs.ErrBadRequest.WithDetail("provider mismatch")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("state expired")
	}

	pc, err := s.loadProvider(ctx, tenantID, provider)
	if err != nil {
		return nil, err
	}
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("provider discovery failed")
	}
	accessToken, err := s.oauth.exchange(ctx, doc, pc.clientID, pc.clientSecret, code, storedRedirect, verifier)
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("token exchange failed")
	}
	ui, err := s.oauth.userinfo(ctx, doc, accessToken)
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("userinfo failed")
	}
	if ui.Email == "" {
		return nil, errs.ErrBadRequest.WithDetail("provider did not return an email")
	}

	userID, err := s.findOrCreateUser(ctx, tenantID, provider, ui)
	if err != nil {
		return nil, err
	}

	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.social_login_codes (code_hash, user_id, tenant_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`, codeHash, userID, tenantID, time.Now().UTC().Add(socialCodeTTL)); err != nil {
		return nil, err
	}
	return &CallbackResult{Code: rawCode, ReturnTo: returnTo, UserID: userID, TenantID: tenantID}, nil
}

// EnabledProviderNames returns the names of a tenant's enabled social providers
// (for the hosted login app to render buttons). Satisfies oidc.ProviderLister.
func (s *Service) EnabledProviderNames(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT provider FROM tenant.social_providers WHERE tenant_id = $1 AND enabled ORDER BY provider`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// StartLoginSession mints a hosted-login SSO session for a social-authenticated
// user, so social login can drive the OAuth authorize/consent flow.
func (s *Service) StartLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	return s.auth.CreateLoginSession(ctx, userID, ip, ua)
}

// findOrCreateUser links the external identity to an existing user (matched by
// provider subject, then by globally-unique email) or provisions a new
// password-less one. All in one tx so concurrent logins can't duplicate rows.
func (s *Service) findOrCreateUser(ctx context.Context, tenantID uuid.UUID, provider string, ui userInfo) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM "user".external_identities
		WHERE tenant_id = $1 AND provider = $2 AND subject = $3
	`, tenantID, provider, ui.Subject).Scan(&userID)
	if err == nil {
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	// No linked identity yet: reuse a user with the same (globally-unique)
	// email, else create one.
	err = tx.QueryRow(ctx, `
		SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`, ui.Email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		var displayName any
		if ui.Name != "" {
			displayName = ui.Name
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO "user".users (tenant_id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, NOW(), $3, 'active')
			RETURNING id
		`, tenantID, ui.Email, displayName).Scan(&userID); err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, provider, subject) DO NOTHING
	`, userID, tenantID, provider, ui.Subject, ui.Email); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// ExchangeLogin trades a one-time social login code for a Qeet token pair.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
	if rawCode == "" {
		return nil, errs.ErrBadRequest.WithDetail("code required")
	}
	codeHash := codes.Hash(rawCode)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		userID    uuid.UUID
		tenantID  uuid.UUID
		expiresAt time.Time
		usedAt    *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT user_id, tenant_id, expires_at, used_at
		FROM auth.social_login_codes WHERE code_hash = $1 FOR UPDATE
	`, codeHash).Scan(&userID, &tenantID, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid code")
	}
	if err != nil {
		return nil, err
	}
	if usedAt != nil {
		return nil, errs.ErrUnauthorized.WithDetail("code already used")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("code expired")
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.social_login_codes SET used_at = NOW() WHERE code_hash = $1`, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, userID, tenantID, ip, ua, "social")
}

type Handler struct {
	Service *Service
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only); set
	// from SERVICE_ENV != "dev".
	CookieSecure bool
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/social/providers", h.upsertProvider)
	r.Get("/tenants/{tenantID}/social/providers", h.listProviders)
	r.Get("/users/{userID}/social/identities", h.listIdentities)
	r.Delete("/social/identities/{id}", h.unlink)
}

// MountPublic mounts the browser-facing OAuth ceremony, which carries no JWT.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/social/{provider}/start", h.start)
	r.Get("/social/{provider}/callback", h.callback)
	r.Post("/social/exchange", h.exchange)
}

// callbackURL reconstructs the public callback URL the upstream provider must
// redirect back to; it must match between start and the token exchange.
func callbackURL(r *http.Request, provider string) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/v1/social/" + provider + "/callback"
}

func (h *Handler) upsertProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID // scope comes from the principal, never the body
	p, err := h.Service.UpsertProvider(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) listProviders(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if tid != tenantID {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
		return
	}
	out, err := h.Service.ListProviders(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) listIdentities(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListIdentities(r.Context(), uid, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) unlink(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Unlink(r.Context(), id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// start redirects the browser to the provider's authorization endpoint.
// Tenant is supplied as ?tenant=<slug> or ?tenant_id=<uuid> (no JWT here).
// ?return_to=<url> opts into the hosted flow: the callback sets the SSO cookie
// and bounces back there instead of handing a one-time code to the SPA.
func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	tenantRef := r.URL.Query().Get("tenant")
	if tenantRef == "" {
		tenantRef = r.URL.Query().Get("tenant_id")
	}
	authURL, err := h.Service.BeginLogin(r.Context(), provider, tenantRef, callbackURL(r, provider), r.URL.Query().Get("return_to"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// callback handles the provider redirect. In the hosted flow (return_to set) it
// establishes the SSO cookie and bounces back to the authorize URL; otherwise it
// bounces to the SPA with a one-time code (tokens are never placed in the URL).
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	res, err := h.Service.CompleteCallback(r.Context(), provider, q.Get("state"), q.Get("code"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.ReturnTo != "" {
		// Hosted flow: set the SSO cookie and return to /oauth/authorize.
		if raw, serr := h.Service.StartLoginSession(r.Context(), res.UserID, httpx.ClientIP(r), r.UserAgent()); serr == nil {
			auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
		}
		http.Redirect(w, r, res.ReturnTo, http.StatusFound)
		return
	}
	target := h.Service.appBaseURL + "/auth/social/callback?code=" + url.QueryEscape(res.Code)
	http.Redirect(w, r, target, http.StatusFound)
}

type exchangeInput struct {
	Code string `json:"code"`
}

// exchange trades a one-time social login code for a token pair.
func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var in exchangeInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.ExchangeLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}
