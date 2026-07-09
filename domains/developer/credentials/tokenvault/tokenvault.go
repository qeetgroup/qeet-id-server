// Package tokenvault is a per-tenant encrypted store for third-party OAuth
// tokens (Slack, GitHub, Google, or any custom OAuth2 provider an admin
// registers). A user connects their account once via a standard
// authorization-code ceremony; from then on, a caller (typically an AI agent
// or backend integration acting on that user's behalf) asks for a live
// access token via GetAccessToken and never sees — or needs to handle — the
// underlying refresh token. Encryption reuses the same KeyProvider (KMS or
// static key) as the sibling secrets vault (see
// domains/developer/credentials/secrets), so both vaults are backed by the
// same key-management story.
package tokenvault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	secret "github.com/qeetgroup/qeet-id/domains/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
)

const connectStateTTL = 10 * time.Minute

// expirySkew treats a token as due for refresh slightly before it actually
// expires, so a slow caller never hands out a token that dies mid-flight.
const expirySkew = 60 * time.Second

// Provider is a tenant's registered OAuth2 endpoint config for one
// third-party service. ClientSecret is never returned by the API.
type Provider struct {
	ID           uuid.UUID `json:"id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	AuthorizeURL string    `json:"authorize_url"`
	TokenURL     string    `json:"token_url"`
	Scopes       string    `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// GrantMeta is the non-secret view of a connected account.
type GrantMeta struct {
	Provider          string     `json:"provider"`
	ExternalAccountID *string    `json:"external_account_id,omitempty"`
	Scope             *string    `json:"scope,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Service struct {
	pool *pgxpool.Pool
	gcm  cipher.AEAD
	http *http.Client
}

// NewService builds the vault, unwrapping the data key from kp once — the
// same KeyProvider interface (and typically the same provider instance) the
// secrets vault uses, so both are keyed off one KMS/static-key setup.
func NewService(ctx context.Context, pool *pgxpool.Pool, kp secret.KeyProvider) (*Service, error) {
	key, err := kp.DataKey(ctx)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Service{pool: pool, gcm: gcm, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (s *Service) encrypt(plaintext string) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, s.gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = s.gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nonce, nil
}

func (s *Service) decrypt(ciphertext, nonce []byte) (string, error) {
	pt, err := s.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// --- provider registration (admin) ---

type RegisterProviderInput struct {
	Provider     string `json:"provider" validate:"required"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	AuthorizeURL string `json:"authorize_url" validate:"required,url"`
	TokenURL     string `json:"token_url" validate:"required,url"`
	Scopes       string `json:"scopes"`
}

func (s *Service) RegisterProvider(ctx context.Context, tenantID uuid.UUID, in RegisterProviderInput) (*Provider, error) {
	var p Provider
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.token_vault_providers (tenant_id, provider, client_id, client_secret, authorize_url, token_url, scopes)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, provider) DO UPDATE SET
			client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret,
			authorize_url = EXCLUDED.authorize_url, token_url = EXCLUDED.token_url,
			scopes = EXCLUDED.scopes, updated_at = NOW()
		RETURNING id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at
	`, tenantID, in.Provider, in.ClientID, in.ClientSecret, in.AuthorizeURL, in.TokenURL, in.Scopes).
		Scan(&p.ID, &p.Provider, &p.ClientID, &p.AuthorizeURL, &p.TokenURL, &p.Scopes, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) ListProviders(ctx context.Context, tenantID uuid.UUID) ([]Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at
		FROM tenant.token_vault_providers WHERE tenant_id = $1 ORDER BY provider
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Provider, 0)
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.Provider, &p.ClientID, &p.AuthorizeURL, &p.TokenURL, &p.Scopes, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) DeleteProvider(ctx context.Context, tenantID uuid.UUID, provider string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM tenant.token_vault_providers WHERE tenant_id = $1 AND provider = $2`, tenantID, provider)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (s *Service) providerConfig(ctx context.Context, tenantID uuid.UUID, provider string) (clientID, clientSecret, authorizeURL, tokenURL, scopes string, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret, authorize_url, token_url, scopes
		FROM tenant.token_vault_providers WHERE tenant_id = $1 AND provider = $2
	`, tenantID, provider).Scan(&clientID, &clientSecret, &authorizeURL, &tokenURL, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		err = errs.ErrNotFound.WithDetail("provider not registered for this tenant")
	}
	return
}

// --- connect ceremony ---

// callbackURL is the vault's own fixed OAuth2 redirect target — never
// caller-supplied, so there's no open-redirect surface on the return leg.
func callbackURL(base string) string { return base + "/v1/vault/tokens/callback" }

// BeginConnect starts an authorization-code ceremony for (tenantID, userID)
// to connect provider, returning the URL to redirect the user's browser to.
func (s *Service) BeginConnect(ctx context.Context, tenantID, userID uuid.UUID, provider, base string) (string, error) {
	clientID, _, authorizeURL, _, scopes, err := s.providerConfig(ctx, tenantID, provider)
	if err != nil {
		return "", err
	}
	state, err := randomState()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO tenant.token_vault_connect_states (state, tenant_id, user_id, provider, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, state, tenantID, userID, provider, time.Now().UTC().Add(connectStateTTL)); err != nil {
		return "", err
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", errs.ErrUnprocessable.WithDetail("provider authorize_url is invalid")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", callbackURL(base))
	q.Set("state", state)
	if scopes != "" {
		q.Set("scope", scopes)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// oauthTokenResponse is the standard OAuth2 token-endpoint JSON shape (RFC
// 6749 §5.1), which Slack/GitHub (with Accept: application/json)/Google/most
// custom providers all return.
type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    any    `json:"expires_in"` // some providers send this as a numeric string
}

func (r oauthTokenResponse) expiresInSeconds() int64 {
	switch v := r.ExpiresIn.(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}

// FinishConnect completes the ceremony: it validates the single-use state,
// exchanges code for tokens, encrypts them, and upserts the grant.
func (s *Service) FinishConnect(ctx context.Context, state, code, base string) error {
	var tenantID, userID uuid.UUID
	var provider string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `
		DELETE FROM tenant.token_vault_connect_states WHERE state = $1
		RETURNING tenant_id, user_id, provider, expires_at
	`, state).Scan(&tenantID, &userID, &provider, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrBadRequest.WithDetail("invalid or used state")
	}
	if err != nil {
		return err
	}
	if time.Now().After(expiresAt) {
		return errs.ErrBadRequest.WithDetail("connect ceremony expired")
	}

	clientID, clientSecret, _, tokenURL, _, err := s.providerConfig(ctx, tenantID, provider)
	if err != nil {
		return err
	}
	tok, err := s.exchange(ctx, tokenURL, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {callbackURL(base)},
		"client_id":    {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return err
	}
	return s.storeGrant(ctx, tenantID, userID, provider, tok)
}

func (s *Service) storeGrant(ctx context.Context, tenantID, userID uuid.UUID, provider string, tok *oauthTokenResponse) error {
	accessCT, accessNonce, err := s.encrypt(tok.AccessToken)
	if err != nil {
		return err
	}
	var refreshCT, refreshNonce any
	if tok.RefreshToken != "" {
		ct, nonce, err := s.encrypt(tok.RefreshToken)
		if err != nil {
			return err
		}
		refreshCT, refreshNonce = ct, nonce
	}
	var expiresAt any
	if secs := tok.expiresInSeconds(); secs > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(secs) * time.Second)
	}
	tokenType := tok.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	var scopeArg any
	if tok.Scope != "" {
		scopeArg = tok.Scope
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO tenant.token_vault_grants
			(tenant_id, user_id, provider, access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce, token_type, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, user_id, provider) DO UPDATE SET
			access_token_ct = EXCLUDED.access_token_ct, access_token_nonce = EXCLUDED.access_token_nonce,
			refresh_token_ct = COALESCE(EXCLUDED.refresh_token_ct, tenant.token_vault_grants.refresh_token_ct),
			refresh_token_nonce = COALESCE(EXCLUDED.refresh_token_nonce, tenant.token_vault_grants.refresh_token_nonce),
			token_type = EXCLUDED.token_type, scope = EXCLUDED.scope, expires_at = EXCLUDED.expires_at, updated_at = NOW()
	`, tenantID, userID, provider, accessCT, accessNonce, refreshCT, refreshNonce, tokenType, scopeArg, expiresAt)
	return err
}

// exchange POSTs a form-encoded OAuth2 token request and parses the response.
// Shared by the initial code exchange and refresh.
func (s *Service) exchange(ctx context.Context, tokenURL string, form url.Values) (*oauthTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, errs.ErrInternal.WithDetail("token request failed: " + err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.ErrInternal.WithDetail("token endpoint returned " + strconv.Itoa(resp.StatusCode) + ": " + string(bytes.TrimSpace(body)))
	}
	var tok oauthTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, errs.ErrInternal.WithDetail("malformed token response")
	}
	if tok.AccessToken == "" {
		return nil, errs.ErrInternal.WithDetail("token response missing access_token")
	}
	return &tok, nil
}

// --- runtime use ---

// GetAccessToken returns a live access token for (tenantID, userID, provider),
// transparently refreshing it first if it's expired (or about to be) and a
// refresh token is on file. The raw refresh token is never returned to the
// caller — only ever used internally to mint a new access token.
func (s *Service) GetAccessToken(ctx context.Context, tenantID, userID uuid.UUID, provider string) (string, error) {
	var accessCT, accessNonce, refreshCT, refreshNonce []byte
	var expiresAt *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce, expires_at
		FROM tenant.token_vault_grants WHERE tenant_id = $1 AND user_id = $2 AND provider = $3
	`, tenantID, userID, provider).Scan(&accessCT, &accessNonce, &refreshCT, &refreshNonce, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrNotFound.WithDetail("no connected account for this provider")
	}
	if err != nil {
		return "", err
	}

	if expiresAt == nil || time.Now().Before(expiresAt.Add(-expirySkew)) {
		return s.decrypt(accessCT, accessNonce)
	}
	if refreshCT == nil {
		// Expired with no refresh token on file — the caller must reconnect.
		return "", errs.ErrUnauthorized.WithDetail("connected account's token expired and cannot be refreshed")
	}
	refreshToken, err := s.decrypt(refreshCT, refreshNonce)
	if err != nil {
		return "", err
	}
	clientID, clientSecret, _, tokenURL, _, err := s.providerConfig(ctx, tenantID, provider)
	if err != nil {
		return "", err
	}
	tok, err := s.exchange(ctx, tokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return "", err
	}
	// Most providers omit refresh_token on a refresh response, meaning "keep
	// using the one you have" — preserve it rather than losing it.
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	if err := s.storeGrant(ctx, tenantID, userID, provider, tok); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

func (s *Service) ListGrants(ctx context.Context, tenantID, userID uuid.UUID) ([]GrantMeta, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, external_account_id, scope, expires_at, created_at, updated_at
		FROM tenant.token_vault_grants WHERE tenant_id = $1 AND user_id = $2 ORDER BY provider
	`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]GrantMeta, 0)
	for rows.Next() {
		var g GrantMeta
		if err := rows.Scan(&g.Provider, &g.ExternalAccountID, &g.Scope, &g.ExpiresAt, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Service) Disconnect(ctx context.Context, tenantID, userID uuid.UUID, provider string) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM tenant.token_vault_grants WHERE tenant_id = $1 AND user_id = $2 AND provider = $3
	`, tenantID, userID, provider)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// externalScheme mirrors domains/federation/oidc's helper of the same name:
// the request's public scheme, honoring X-Forwarded-Proto from a
// TLS-terminating proxy, so the callback URL registered with a third-party
// provider stays https in production.
func externalScheme(r *http.Request) string {
	if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	if h := r.Host; strings.HasPrefix(h, "localhost") || strings.HasPrefix(h, "127.0.0.1") {
		return "http"
	}
	return "https"
}

func externalBase(r *http.Request) string {
	return externalScheme(r) + "://" + r.Host
}

// --- HTTP ---

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/tenants/{tenantID}/vault/tokens/providers", h.registerProvider)
	r.Get("/tenants/{tenantID}/vault/tokens/providers", h.listProviders)
	r.Delete("/tenants/{tenantID}/vault/tokens/providers/{provider}", h.deleteProvider)
	r.Get("/vault/tokens", h.listGrants)
	r.Get("/vault/tokens/{provider}/connect", h.beginConnect)
	r.Get("/vault/tokens/{provider}/access-token", h.getAccessToken)
	r.Delete("/vault/tokens/{provider}", h.disconnect)
}

// MountPublic mounts the OAuth2 redirect target (no JWT — the third-party
// provider's redirect carries no auth header; the single-use state param is
// the proof).
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/vault/tokens/callback", h.callback)
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

func (h *Handler) registerProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in RegisterProviderInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.RegisterProvider(r.Context(), tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *Handler) listProviders(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListProviders(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) deleteProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteProvider(r.Context(), tenantID, chi.URLParam(r, "provider")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) beginConnect(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	authorizeURL, err := h.Service.BeginConnect(r.Context(), tenantID, userID, chi.URLParam(r, "provider"), externalBase(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorize_url": authorizeURL})
}

// callback is the OAuth2 redirect target. It renders a minimal, self-contained
// confirmation page rather than redirecting to a caller-supplied URL, so there
// is no open-redirect surface on the return leg.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errCode := q.Get("error"); errCode != "" {
		writeCallbackPage(w, false, errCode)
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		writeCallbackPage(w, false, "missing state or code")
		return
	}
	if err := h.Service.FinishConnect(r.Context(), state, code, externalBase(r)); err != nil {
		msg := "connection failed"
		if e := errs.As(err); e != nil {
			msg = e.Message
			if e.Detail != "" {
				msg = e.Detail
			}
		}
		writeCallbackPage(w, false, msg)
		return
	}
	writeCallbackPage(w, true, "")
}

func writeCallbackPage(w http.ResponseWriter, ok bool, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ok {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><body><p>Connected. You can close this window.</p></body></html>`))
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`<!doctype html><html><body><p>Connection failed: ` + htmlEscape(errMsg) + `</p></body></html>`))
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListGrants(r.Context(), tenantID, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// getAccessToken is the "agent-safe" fetch: it hands back a live access
// token, transparently refreshed if needed, and gated the same way the
// generic secrets vault gates vault:<name> access — a scoped principal
// (e.g. an AI agent) needs vault:<provider> or vault:read, and every access
// is audited since a live third-party credential is sensitive.
func (h *Handler) getAccessToken(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	provider := chi.URLParam(r, "provider")
	if !hasVaultScope(p.Scopes, provider) {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("missing vault:"+provider+" (or vault:read) scope"))
		return
	}
	token, err := h.Service.GetAccessToken(r.Context(), tenantID, userID, provider)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, terr := h.Service.pool.Begin(ctx)
	if terr == nil {
		defer tx.Rollback(ctx)
		actorID := p.UserID
		if aerr := audit.Record(ctx, tx, audit.Event{
			TenantID:     &tenantID,
			ActorUserID:  actorID,
			Action:       "vault.tokens.accessed",
			ResourceType: "token_vault_grant",
			IP:           httpx.ClientIP(r),
			UserAgent:    r.UserAgent(),
			RequestID:    httpx.RequestID(r),
			Metadata:     map[string]any{"provider": provider},
		}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_token": token})
}

func hasVaultScope(scopes []string, provider string) bool {
	for _, s := range scopes {
		if s == "vault:read" || s == "vault:"+provider {
			return true
		}
	}
	return false
}

func (h *Handler) disconnect(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Disconnect(r.Context(), tenantID, userID, chi.URLParam(r, "provider")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
