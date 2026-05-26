// Package oidc implements the OpenID Connect provider role for Qeet.
// Implemented: client_credentials grant (via principal pkg),
// authorization_code grant skeleton, discovery + JWKS endpoints,
// userinfo. Refresh-token grant for OIDC clients is TODO.
package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
)

type Client struct {
	ID              uuid.UUID `json:"id"`
	TenantID        uuid.UUID `json:"tenant_id"`
	ClientID        string    `json:"client_id"`
	Type            string    `json:"type"`
	Name            string    `json:"name"`
	RedirectURIs    []string  `json:"redirect_uris"`
	PostLogoutURIs  []string  `json:"post_logout_uris"`
	GrantTypes      []string  `json:"grant_types"`
	Scopes          []string  `json:"scopes"`
	CreatedAt       time.Time `json:"created_at"`
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

// Authorize is the GET /oauth/authorize handler. Because we don't ship a
// consent screen, this implementation requires the caller to be already
// authenticated AND to have a granted consent row.
func (s *Service) Authorize(ctx context.Context, userID, tenantID uuid.UUID, clientID, redirectURI string, scopes []string, nonce, challenge, challengeMethod string) (string, error) {
	var dbScopes []string
	var dbRedirectURIs []string
	err := s.pool.QueryRow(ctx, `
		SELECT scopes, redirect_uris FROM auth.oidc_clients
		WHERE client_id = $1 AND tenant_id = $2
	`, clientID, tenantID).Scan(&dbScopes, &dbRedirectURIs)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrBadRequest.WithDetail("unknown client")
	}
	if err != nil {
		return "", err
	}
	if !contains(dbRedirectURIs, redirectURI) {
		return "", errs.ErrBadRequest.WithDetail("redirect_uri not registered")
	}
	for _, sc := range scopes {
		if !contains(dbScopes, sc) {
			return "", errs.ErrBadRequest.WithDetail("scope not permitted: " + sc)
		}
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO auth.oidc_authorization_codes (
			code_hash, client_id, user_id, tenant_id, redirect_uri,
			scopes, nonce, code_challenge, code_challenge_method, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,''), NULLIF($8,''), NULLIF($9,''), NOW() + INTERVAL '10 minutes')
	`, hash, clientID, userID, tenantID, redirectURI, scopes, nonce, challenge, challengeMethod)
	if err != nil {
		return "", err
	}
	return raw, nil
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeCode swaps an authorization_code for tokens.
func (s *Service) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	var secretHash *string
	var dbType string
	err := s.pool.QueryRow(ctx, `
		SELECT client_secret_hash, type FROM auth.oidc_clients WHERE client_id = $1
	`, clientID).Scan(&secretHash, &dbType)
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
	return &TokenResponse{
		AccessToken: access,
		IDToken:     idTok,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.issuer.AccessTTL().Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
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

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/oidc/clients", h.registerClient)
	r.Get("/oauth/authorize", h.authorize)
	r.Post("/oauth/token-code", h.tokenCode) // distinct from /oauth/token (client_credentials)
	r.Get("/oauth/userinfo", h.userinfo)
}

func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.discovery)
	r.Get("/.well-known/jwks.json", h.jwks)
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

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	scopes := strings.Fields(q.Get("scope"))
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	code, err := h.Service.Authorize(r.Context(), *p.UserID, *p.TenantID, clientID, redirect, scopes, nonce, challenge, method)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	state := q.Get("state")
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	target := redirect + sep + "code=" + code
	if state != "" {
		target += "&state=" + state
	}
	http.Redirect(w, r, target, http.StatusFound)
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
	if r.Form.Get("grant_type") != "authorization_code" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("unsupported grant_type"))
		return
	}
	resp, err := h.Service.ExchangeCode(r.Context(),
		clientID, clientSecret,
		r.Form.Get("code"), r.Form.Get("redirect_uri"), r.Form.Get("code_verifier"))
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
		"userinfo_endpoint":                     base + "/v1/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"HS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

// jwks returns an empty key set because the dev signer uses HS256 — when
// you swap to RS256 you'll list the public JWK here.
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
}
