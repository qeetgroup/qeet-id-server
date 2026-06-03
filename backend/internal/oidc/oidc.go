// Package oidc implements the OpenID Connect provider role for Qeet.
// Implemented: client_credentials grant (via principal pkg),
// authorization_code grant skeleton, discovery + JWKS endpoints,
// userinfo, and the refresh-token grant.
package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
)

type Client struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	ClientID       string    `json:"client_id"`
	Type           string    `json:"type"`
	Name           string    `json:"name"`
	RedirectURIs   []string  `json:"redirect_uris"`
	PostLogoutURIs []string  `json:"post_logout_uris"`
	GrantTypes     []string  `json:"grant_types"`
	Scopes         []string  `json:"scopes"`
	CreatedAt      time.Time `json:"created_at"`
}

type Service struct {
	pool   *pgxpool.Pool
	issuer *tokens.Issuer
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, issuer: issuer}
}

type CreateClientInput struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	RedirectURIs   []string  `json:"redirect_uris"`
	PostLogoutURIs []string  `json:"post_logout_uris"`
	GrantTypes     []string  `json:"grant_types"`
	Scopes         []string  `json:"scopes"`
}

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an OIDC mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) RegisterClient(ctx context.Context, tx pgx.Tx, in CreateClientInput) (*Client, string, error) {
	if in.Type == "" {
		in.Type = "confidential"
	}
	if len(in.GrantTypes) == 0 {
		in.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "profile", "email"}
	}
	// The columns are NOT NULL DEFAULT '{}'; a nil Go slice encodes as SQL NULL,
	// so coalesce to empty to honour callers that omit these arrays.
	if in.RedirectURIs == nil {
		in.RedirectURIs = []string{}
	}
	if in.PostLogoutURIs == nil {
		in.PostLogoutURIs = []string{}
	}
	clientID := "qci_" + uuid.NewString()
	var secretHash *string
	var raw string
	if in.Type == "confidential" {
		secret, _, err := codes.URLToken()
		if err != nil {
			return nil, "", err
		}
		raw = secret
		hash, err := password.Hash(secret)
		if err != nil {
			return nil, "", err
		}
		secretHash = &hash
	}
	var c Client
	err := tx.QueryRow(ctx, `
		INSERT INTO auth.oidc_clients (
			tenant_id, client_id, client_secret_hash, type, name,
			redirect_uris, post_logout_uris, grant_types, scopes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, tenant_id, client_id, type, name, redirect_uris,
		          post_logout_uris, grant_types, scopes, created_at
	`, in.TenantID, clientID, secretHash, in.Type, in.Name,
		in.RedirectURIs, in.PostLogoutURIs, in.GrantTypes, in.Scopes).
		Scan(&c.ID, &c.TenantID, &c.ClientID, &c.Type, &c.Name,
			&c.RedirectURIs, &c.PostLogoutURIs, &c.GrantTypes, &c.Scopes, &c.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	return &c, raw, nil
}

// Authorize validates an authorization request for an already-authenticated
// user and mints a one-time authorization code. The client's tenant is derived
// from the client itself (the browser-facing flow has no user JWT to carry it).
// Returns the raw code and the resolved tenant id.
func (s *Service) Authorize(ctx context.Context, userID uuid.UUID, clientID, redirectURI string, scopes []string, nonce, challenge, challengeMethod string) (string, uuid.UUID, error) {
	var tenantID uuid.UUID
	var dbScopes []string
	var dbRedirectURIs []string
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, scopes, redirect_uris FROM auth.oidc_clients
		WHERE client_id = $1
	`, clientID).Scan(&tenantID, &dbScopes, &dbRedirectURIs)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrBadRequest.WithDetail("unknown client")
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	if !contains(dbRedirectURIs, redirectURI) {
		return "", uuid.Nil, errs.ErrBadRequest.WithDetail("redirect_uri not registered")
	}
	for _, sc := range scopes {
		if !contains(dbScopes, sc) {
			return "", uuid.Nil, errs.ErrBadRequest.WithDetail("scope not permitted: " + sc)
		}
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", uuid.Nil, err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO auth.oidc_authorization_codes (
			code_hash, client_id, user_id, tenant_id, redirect_uri,
			scopes, nonce, code_challenge, code_challenge_method, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,''), NULLIF($8,''), NULLIF($9,''), NOW() + INTERVAL '10 minutes')
	`, hash, clientID, userID, tenantID, redirectURI, scopes, nonce, challenge, challengeMethod)
	if err != nil {
		return "", uuid.Nil, err
	}
	return raw, tenantID, nil
}

// ClientName resolves a client's display name and tenant from its client_id —
// used to render the hosted login/consent screens. Returns ErrNotFound for an
// unknown client.
func (s *Service) ClientName(ctx context.Context, clientID string) (name string, tenantID uuid.UUID, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT name, tenant_id FROM auth.oidc_clients WHERE client_id = $1`, clientID).
		Scan(&name, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrNotFound
	}
	return name, tenantID, err
}

// ValidatePostLogoutRedirect reports whether uri is one of the client's
// registered post-logout redirect URIs (RP-Initiated Logout).
func (s *Service) ValidatePostLogoutRedirect(ctx context.Context, clientID, uri string) (bool, error) {
	var uris []string
	err := s.pool.QueryRow(ctx,
		`SELECT post_logout_uris FROM auth.oidc_clients WHERE client_id = $1`, clientID).Scan(&uris)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return contains(uris, uri), nil
}

// HasConsent reports whether the user has already granted the client every
// requested scope (so the consent screen can be skipped).
func (s *Service) HasConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) (bool, error) {
	var granted []string
	err := s.pool.QueryRow(ctx,
		`SELECT scopes FROM auth.oidc_consents WHERE user_id = $1 AND client_id = $2`,
		userID, clientID).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, sc := range scopes {
		if !contains(granted, sc) {
			return false, nil
		}
	}
	return true, nil
}

// GrantConsent records the user's approval of a client for the given scopes,
// replacing any prior grant for that (user, client) pair.
func (s *Service) GrantConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.oidc_consents (user_id, client_id, scopes, granted_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = $3, granted_at = NOW()
	`, userID, clientID, scopes)
	return err
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// authenticateClient verifies a confidential client's secret and returns its grant types.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) ([]string, error) {
	var secretHash *string
	var dbType string
	var grantTypes []string
	err := s.pool.QueryRow(ctx, `
		SELECT client_secret_hash, type, grant_types FROM auth.oidc_clients WHERE client_id = $1
	`, clientID).Scan(&secretHash, &dbType, &grantTypes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown client")
	}
	if err != nil {
		return nil, err
	}
	if dbType == "confidential" {
		if secretHash == nil || !password.Verify(*secretHash, clientSecret) {
			return nil, errs.ErrUnauthorized.WithDetail("invalid client secret")
		}
	}
	return grantTypes, nil
}

// ExchangeCode swaps an authorization_code for tokens.
func (s *Service) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	grantTypes, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	hash := codes.Hash(code)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		userID, tenantID uuid.UUID
		dbRedirect       string
		scopes           []string
		nonce            *string
		challenge        *string
		method           *string
		expiresAt        time.Time
		usedAt           *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT user_id, tenant_id, redirect_uri, scopes, nonce, code_challenge, code_challenge_method, expires_at, used_at
		FROM auth.oidc_authorization_codes
		WHERE code_hash = $1 AND client_id = $2
		FOR UPDATE
	`, hash, clientID).Scan(&userID, &tenantID, &dbRedirect, &scopes, &nonce, &challenge, &method, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("invalid code")
	}
	if err != nil {
		return nil, err
	}
	if usedAt != nil {
		return nil, errs.ErrBadRequest.WithDetail("code already used")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("code expired")
	}
	if dbRedirect != redirectURI {
		return nil, errs.ErrBadRequest.WithDetail("redirect_uri mismatch")
	}
	if challenge != nil && *challenge != "" {
		if codeVerifier == "" {
			return nil, errs.ErrBadRequest.WithDetail("code_verifier required")
		}
		// We support S256 only (the recommended PKCE method).
		if method == nil || *method != "S256" {
			return nil, errs.ErrBadRequest.WithDetail("unsupported code_challenge_method")
		}
		if codes.Hash(codeVerifier) != *challenge {
			return nil, errs.ErrBadRequest.WithDetail("invalid code_verifier")
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.oidc_authorization_codes SET used_at = NOW() WHERE code_hash = $1`, hash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	sessionID := uuid.New()
	access, _, err := s.issuer.IssueAccess(userID, tenantID, sessionID, strings.Join(scopes, " "))
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(userID, tenantID, clientID, derefStr(nonce))
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	refresh := ""
	if contains(grantTypes, "refresh_token") {
		refresh, err = s.issueRefreshToken(ctx, clientID, userID, tenantID, scopes)
		if err != nil {
			return nil, err
		}
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// issueRefreshToken persists a refresh token bound to the client+user and returns the raw value.
func (s *Service) issueRefreshToken(ctx context.Context, clientID string, userID, tenantID uuid.UUID, scopes []string) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	exp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	_, err = s.pool.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, hash, clientID, userID, tenantID, scopes, exp)
	if err != nil {
		return "", err
	}
	return raw, nil
}

// RefreshToken handles the refresh_token grant: it rotates the presented token and re-issues
// tokens scoped to the original grant. Replay of a used token revokes every live token for the (client, user).
func (s *Service) RefreshToken(ctx context.Context, clientID, clientSecret, rawRefresh string) (*TokenResponse, error) {
	if _, err := s.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	if rawRefresh == "" {
		return nil, errs.ErrBadRequest.WithDetail("refresh_token required")
	}
	hash := tokens.HashRefresh(rawRefresh)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		id          uuid.UUID
		rowClientID string
		userID      uuid.UUID
		tenantID    uuid.UUID
		scopes      []string
		expiresAt   time.Time
		usedAt      *time.Time
		revokedAt   *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, client_id, user_id, tenant_id, scopes, expires_at, used_at, revoked_at
		FROM auth.oidc_refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, hash).Scan(&id, &rowClientID, &userID, &tenantID, &scopes, &expiresAt, &usedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown refresh token")
	}
	if err != nil {
		return nil, err
	}
	// A refresh token may only be redeemed by the client it was issued to.
	if rowClientID != clientID {
		return nil, errs.ErrUnauthorized.WithDetail("client mismatch")
	}
	if revokedAt != nil {
		return nil, errs.ErrUnauthorized.WithDetail("refresh token revoked")
	}
	if usedAt != nil {
		// Reuse — assume theft: revoke every live token for this (client, user) and audit it.
		if err := s.handleRefreshReuse(ctx, tx, clientID, userID, tenantID, id); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrUnauthorized.WithDetail("refresh token reuse — tokens revoked")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("refresh token expired")
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	newExp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	var newID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, newHash, clientID, userID, tenantID, scopes, newExp).Scan(&newID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.oidc_refresh_tokens SET used_at = NOW(), replaced_by = $1 WHERE id = $2
	`, newID, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	access, _, err := s.issuer.IssueAccess(userID, tenantID, uuid.New(), strings.Join(scopes, " "))
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(userID, tenantID, clientID, "")
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: newRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// handleRefreshReuse revokes every live refresh token for a (client, user) on replay and audits it.
func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx, clientID string, userID, tenantID, tokenID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `
		UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
		WHERE client_id = $1 AND user_id = $2 AND revoked_at IS NULL
	`, clientID, userID); err != nil {
		return err
	}
	tid, uid, rid := tenantID, userID, tokenID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "oidc.refresh_reuse_detected",
		ResourceType: "oidc_refresh_token",
		ResourceID:   &rid,
		Metadata: map[string]any{
			"client_id":        clientID,
			"refresh_token_id": tokenID,
			"reason":           "refresh_token_reuse",
		},
	})
}

func (s *Service) signIDToken(userID, tenantID uuid.UUID, audience, nonce string) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(s.issuer.AccessTTL())
	claims := jwt.MapClaims{
		"iss":       s.issuer.JWTIssuer(),
		"sub":       userID.String(),
		"aud":       audience,
		"exp":       exp.Unix(),
		"iat":       now.Unix(),
		"tenant_id": tenantID.String(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return s.issuer.Sign(claims)
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// SessionManager resolves and revokes the hosted-login SSO cookie. Satisfied by
// *auth.Service; an interface keeps the dependency one-way.
type SessionManager interface {
	ResolveLoginSession(ctx context.Context, raw string) (uuid.UUID, error)
	RevokeLoginSession(ctx context.Context, raw string) error
}

// ProviderLister lists a tenant's enabled social providers, so the hosted login
// app can render the right social buttons. Satisfied by *social.Service.
type ProviderLister interface {
	EnabledProviderNames(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

type Handler struct {
	Service *Service
	// Sessions resolves the hosted-login SSO cookie for the authorize/consent
	// flow. LoginBaseURL is the origin of the hosted login app (qeetid-login)
	// the browser is redirected to for login/consent. Providers lists a tenant's
	// social providers for the login-context endpoint (optional).
	Sessions     SessionManager
	Providers    ProviderLister
	LoginBaseURL string
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only) when
	// clearing it on logout; set from SERVICE_ENV != "dev".
	CookieSecure bool
}

// Mount registers the authenticated admin/RP endpoints (require a user JWT or
// API key): client registration, userinfo (bearer access token), and grant
// administration.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/oidc/clients", h.registerClient)
	r.Get("/oauth/userinfo", h.userinfo)
	r.Get("/tenants/{tenantID}/oauth/grants", h.listGrants)
	r.Delete("/tenants/{tenantID}/oauth/grants/{id}", h.revokeGrant)
}

// MountBrowser registers the browser/RP-facing OAuth endpoints that authenticate
// via the SSO cookie or client credentials (not a user JWT), so they live in
// the public group. token-code is client-credential M2M and is CSRF-exempt in
// the router; authorize (GET) and decision (cookie POST) are not.
func (h *Handler) MountBrowser(r chi.Router) {
	r.Get("/oauth/authorize", h.authorize)
	r.Post("/oauth/authorize/decision", h.decision)
	r.Post("/oauth/token-code", h.tokenCode)
	r.Get("/oauth/login-context", h.loginContext)
	r.Get("/oauth/logout", h.endSession)  // RP-Initiated Logout
	r.Post("/oauth/logout", h.endSession) // (some RPs POST)
	// Device Authorization Grant (RFC 8628). device_authorization is
	// client-authenticated M2M (CSRF-exempt in the router, like token-code);
	// the device context + decision endpoints are SSO-cookie gated like
	// authorize/decision (the hosted /device page posts the user's choice).
	r.Post("/oauth/device_authorization", h.deviceAuthorization)
	r.Get("/oauth/device", h.deviceContext)
	r.Post("/oauth/device/decision", h.deviceDecision)
}

// loginContext gives the hosted login app what it needs to render itself for a
// given client_id: the client's display name, its tenant, and the tenant's
// enabled social providers.
func (h *Handler) loginContext(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	name, tenantID, err := h.Service.ClientName(r.Context(), clientID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	providers := []string{}
	if h.Providers != nil {
		if p, perr := h.Providers.EnabledProviderNames(r.Context(), tenantID); perr == nil {
			providers = p
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_name": name,
		"tenant_id":   tenantID,
		"providers":   providers,
	})
}

func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.discovery)
	r.Get("/.well-known/jwks.json", h.jwks)
	// Client-authenticated, machine-to-machine; CSRF-exempt in the router.
	r.Post("/oauth/revoke", h.revoke)         // RFC 7009
	r.Post("/oauth/introspect", h.introspect) // RFC 7662
}

func (h *Handler) registerClient(w http.ResponseWriter, r *http.Request) {
	var in CreateClientInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	c, secret, err := h.Service.RegisterClient(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		} else {
			actorType = "user"
		}
	}
	tenantID := c.TenantID
	resourceID := c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "oidc.client_registered",
		ResourceType: "oidc_client",
		ResourceID:   &resourceID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata: map[string]any{
			"client_id":   c.ClientID,
			"type":        c.Type,
			"name":        c.Name,
			"grant_types": c.GrantTypes,
			"scopes":      c.Scopes,
		},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp := map[string]any{"client": c}
	if secret != "" {
		resp["client_secret"] = secret
		resp["warning"] = "secret shown once"
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// authorize is the browser-facing GET /oauth/authorize. The user is identified
// by the hosted-login SSO cookie (not a JWT). If not signed in, the browser is
// sent to the hosted login; if signed in but the client lacks consent, to the
// hosted consent screen; otherwise a code is minted and the browser bounced
// back to the RP's redirect_uri.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	scopes := strings.Fields(q.Get("scope"))

	userID, ok := h.sessionUser(r)
	if !ok {
		ret := url.QueryEscape(currentURL(r))
		http.Redirect(w, r, h.LoginBaseURL+"/login?return_to="+ret, http.StatusFound)
		return
	}

	has, err := h.Service.HasConsent(r.Context(), userID, clientID, scopes)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !has {
		// Hand off to the hosted consent screen, echoing the authorize params
		// so it can post them back to the decision endpoint.
		http.Redirect(w, r, h.LoginBaseURL+"/consent?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	code, _, err := h.Service.Authorize(r.Context(), userID, clientID, redirect,
		scopes, q.Get("nonce"), q.Get("code_challenge"), q.Get("code_challenge_method"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, appendQuery(redirect, "code", code, "state", q.Get("state")), http.StatusFound)
}

type decisionInput struct {
	Approve             bool   `json:"approve"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// decision records the consent decision from the hosted consent screen. The
// user is identified by the SSO cookie. It returns (as JSON) the URL the
// consent SPA should navigate to: a code on approval, or error=access_denied on
// deny.
func (h *Handler) decision(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.sessionUser(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in decisionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !in.Approve {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"redirect": appendQuery(in.RedirectURI, "error", "access_denied", "state", in.State),
		})
		return
	}
	scopes := strings.Fields(in.Scope)
	if err := h.Service.GrantConsent(r.Context(), userID, in.ClientID, scopes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	code, _, err := h.Service.Authorize(r.Context(), userID, in.ClientID, in.RedirectURI,
		scopes, in.Nonce, in.CodeChallenge, in.CodeChallengeMethod)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"redirect": appendQuery(in.RedirectURI, "code", code, "state", in.State),
	})
}

// endSession is the OIDC RP-Initiated Logout endpoint. It clears the hosted SSO
// session + cookie, then — if the client supplied a registered
// post_logout_redirect_uri — redirects there (carrying state); otherwise it
// shows the hosted logged-out page.
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.LoginSessionCookie); err == nil {
		_ = h.Sessions.RevokeLoginSession(r.Context(), c.Value)
	}
	auth.ClearLoginSessionCookie(w, h.CookieSecure)

	q := r.URL.Query()
	redirect := q.Get("post_logout_redirect_uri")
	clientID := q.Get("client_id")
	if redirect != "" && clientID != "" {
		if ok, err := h.Service.ValidatePostLogoutRedirect(r.Context(), clientID, redirect); err == nil && ok {
			http.Redirect(w, r, appendQuery(redirect, "state", q.Get("state")), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, h.LoginBaseURL+"/logged-out", http.StatusFound)
}

// sessionUser resolves the hosted-login SSO cookie to a user id.
func (h *Handler) sessionUser(r *http.Request) (uuid.UUID, bool) {
	c, err := r.Cookie(auth.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, false
	}
	uid, err := h.Sessions.ResolveLoginSession(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, false
	}
	return uid, true
}

// currentURL reconstructs the absolute URL of the current request (for the
// login redirect's return_to).
func currentURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// appendQuery appends key/value pairs (skipping empty values) to a URL that may
// already carry a query string.
func appendQuery(base string, kv ...string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	out := base
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		out += sep + kv[i] + "=" + url.QueryEscape(kv[i+1])
		sep = "&"
	}
	return out
}

func (h *Handler) tokenCode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	var resp *TokenResponse
	var err error
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		resp, err = h.Service.ExchangeCode(r.Context(),
			clientID, clientSecret,
			r.Form.Get("code"), r.Form.Get("redirect_uri"), r.Form.Get("code_verifier"))
	case "refresh_token":
		resp, err = h.Service.RefreshToken(r.Context(),
			clientID, clientSecret, r.Form.Get("refresh_token"))
	case "urn:ietf:params:oauth:grant-type:device_code":
		// RFC 8628 §3.4 polling. The device authenticates with its client_id +
		// device_code; the device_code itself is the proof, so a client_secret is
		// not required (device clients are typically public). Errors here use the
		// RFC 6749 §5.2 flat {"error","error_description"} shape OAuth clients
		// parse, rendered by writeOAuthError.
		resp, err = h.Service.DeviceToken(r.Context(), clientID, r.Form.Get("device_code"))
		if err != nil {
			var oe *oauthError
			if errors.As(err, &oe) {
				writeOAuthError(w, oe)
				return
			}
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	default:
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("unsupported grant_type"))
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// clientCreds parses OAuth client credentials from the form body or HTTP Basic
// auth (the two RFC 6749 §2.3.1 mechanisms). Shared by revoke + introspect.
func (h *Handler) clientCreds(r *http.Request) (id, secret string, ok bool) {
	if err := r.ParseForm(); err != nil {
		return "", "", false
	}
	id = r.Form.Get("client_id")
	secret = r.Form.Get("client_secret")
	if u, p, has := r.BasicAuth(); has {
		id, secret = u, p
	}
	return id, secret, true
}

// revoke is the RFC 7009 token-revocation endpoint. It always answers 200 with
// an empty body on success (including for unknown tokens).
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := h.clientCreds(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	if err := h.Service.RevokeToken(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// introspect is the RFC 7662 token-introspection endpoint.
func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := h.clientCreds(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	resp, err := h.Service.Introspect(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"sub":       p.UserID,
		"tenant_id": p.TenantID,
	})
}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	base := "http://" + r.Host
	if r.TLS != nil {
		base = "https://" + r.Host
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/v1/oauth/authorize",
		"token_endpoint":                        base + "/v1/oauth/token-code",
		"device_authorization_endpoint":         base + "/v1/oauth/device_authorization",
		"userinfo_endpoint":                     base + "/v1/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"introspection_endpoint":                base + "/oauth/introspect",
		"end_session_endpoint":                  base + "/v1/oauth/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{h.Service.issuer.Alg()},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// jwks publishes the public signing keys (active + any retired key still in its
// rotation grace window) so any relying party can verify Qeet-issued ID/access
// tokens. Keys are ES256 over EC P-256; each `kid` matches the token's `kid`
// header (an RFC 7638 JWK thumbprint).
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": h.Service.issuer.JWKS()})
}

// =====================================================================
// OAuth 2.0 token revocation (RFC 7009) & introspection (RFC 7662)
// =====================================================================

// RevokeToken implements RFC 7009. After client authentication, the presented
// refresh token is revoked if it belongs to the calling client. Access tokens
// are stateless ES256 JWTs and can't be revoked individually, so they're a
// no-op. Per the RFC, an unknown or already-revoked token is still a success —
// the only error paths are bad client auth or a DB failure.
func (s *Service) RevokeToken(ctx context.Context, clientID, clientSecret, token, hint string) error {
	if _, err := s.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return err
	}
	if token == "" || hint == "access_token" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE auth.oidc_refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL
	`, tokens.HashRefresh(token), clientID)
	return err
}

// Introspect implements RFC 7662. After client authentication it reports
// whether the token is active and, if so, its metadata. It recognises both our
// ES256 access tokens (verified statelessly) and stored OIDC refresh tokens.
// token_type_hint, when given, picks which check to run first/only.
func (s *Service) Introspect(ctx context.Context, clientID, clientSecret, token, hint string) (map[string]any, error) {
	if _, err := s.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	inactive := map[string]any{"active": false}
	if token == "" {
		return inactive, nil
	}

	// Access token (stateless JWT) — unless the hint says it's a refresh token.
	if hint != "refresh_token" {
		if claims, err := s.issuer.VerifyAccess(token); err == nil {
			out := map[string]any{
				"active":     true,
				"token_type": "Bearer",
				"sub":        claims.Subject,
				"scope":      claims.Scope,
				"iss":        s.issuer.JWTIssuer(),
				"aud":        s.issuer.JWTAudience(),
			}
			if claims.ExpiresAt != nil {
				out["exp"] = claims.ExpiresAt.Unix()
			}
			if claims.IssuedAt != nil {
				out["iat"] = claims.IssuedAt.Unix()
			}
			if claims.TenantID != uuid.Nil {
				out["tenant_id"] = claims.TenantID
			}
			if claims.SessionID != uuid.Nil {
				out["sid"] = claims.SessionID
			}
			return out, nil
		}
	}

	// Refresh token (opaque, stored hashed) — unless the hint says access_token.
	if hint != "access_token" {
		var (
			rowClientID         string
			userID, tenantID    uuid.UUID
			scopes              []string
			issuedAt, expiresAt time.Time
			usedAt, revokedAt   *time.Time
		)
		err := s.pool.QueryRow(ctx, `
			SELECT client_id, user_id, tenant_id, scopes, issued_at, expires_at, used_at, revoked_at
			FROM auth.oidc_refresh_tokens WHERE token_hash = $1
		`, tokens.HashRefresh(token)).Scan(&rowClientID, &userID, &tenantID, &scopes, &issuedAt, &expiresAt, &usedAt, &revokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return inactive, nil
		}
		if err != nil {
			return nil, err
		}
		// Active = not revoked, not yet rotated (used), and unexpired.
		if revokedAt != nil || usedAt != nil || !time.Now().Before(expiresAt) {
			return inactive, nil
		}
		return map[string]any{
			"active":     true,
			"token_type": "refresh_token",
			"client_id":  rowClientID,
			"sub":        userID,
			"tenant_id":  tenantID,
			"scope":      strings.Join(scopes, " "),
			"iat":        issuedAt.Unix(),
			"exp":        expiresAt.Unix(),
		}, nil
	}

	return inactive, nil
}

// =====================================================================
// OAuth grant administration (live OIDC refresh-token grants)
// =====================================================================

// Grant is the current (non-revoked, non-rotated, unexpired) refresh token in
// an OIDC authorization_code grant chain — what an admin sees as an active
// "access token" for a (client, user) pair.
type Grant struct {
	ID        uuid.UUID `json:"id"`
	ClientID  string    `json:"client_id"`
	UserID    uuid.UUID `json:"user_id"`
	UserEmail string    `json:"user_email"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) ListGrants(ctx context.Context, tenantID uuid.UUID) ([]Grant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.client_id, t.user_id, COALESCE(u.email, ''), t.scopes, t.issued_at, t.expires_at
		FROM auth.oidc_refresh_tokens t
		LEFT JOIN "user".users u ON u.id = t.user_id
		WHERE t.tenant_id = $1 AND t.revoked_at IS NULL AND t.replaced_by IS NULL AND t.expires_at > NOW()
		ORDER BY t.issued_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.ClientID, &g.UserID, &g.UserEmail, &g.Scopes, &g.IssuedAt, &g.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrant revokes the entire (client, user) refresh-token chain the given
// token belongs to, so a rotated sibling can't keep the grant alive. Returns
// the client_id for the audit row.
func (s *Service) RevokeGrant(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, uuid.UUID, error) {
	var clientID string
	var userID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT client_id, user_id FROM auth.oidc_refresh_tokens WHERE id = $1 AND tenant_id = $2`, id, tenantID).Scan(&clientID, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrNotFound
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
		WHERE client_id = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
	`, clientID, userID, tenantID); err != nil {
		return "", uuid.Nil, err
	}
	return clientID, userID, nil
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListGrants(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	clientID, targetUser, err := h.Service.RevokeGrant(ctx, tx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
	}
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oauth.grant_revoked", ResourceType: "oidc_grant", ResourceID: &targetUser,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"client_id": clientID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
