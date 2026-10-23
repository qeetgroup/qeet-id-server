// Package tokenvault stores each tenant's third-party OAuth tokens (Slack,
// GitHub, Google, or any registered OAuth2 provider), encrypted. A user connects
// once through an authorization-code flow; GetAccessToken then returns a live
// access token, never the refresh token.
package tokenvault

import (
	"context"
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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
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

// Service stores each tenant's OAuth provider settings and its users'
// third-party tokens, encrypted at rest.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	box    *envelope.Cipher
	http   *http.Client
	egress *egress.Policy
}

// NewService builds the vault, unwrapping the data key from kp once — the
// same KeyProvider interface (and typically the same provider instance) the
// secrets vault uses, so both are keyed off one KMS/static-key setup.
func NewService(ctx context.Context, pool *pgxpool.Pool, kp secret.KeyProvider, policies ...*egress.Policy) (*Service, error) {
	key, err := kp.DataKey(ctx)
	if err != nil {
		return nil, err
	}
	box, err := envelope.New(key)
	if err != nil {
		return nil, err
	}
	policy := egress.PublicPolicy(policies...)
	return &Service{pool: pool, q: dbgen.New(pool), box: box, http: policy.HTTPClient(10 * time.Second), egress: policy}, nil
}

// tsPtr converts a pgtype.Timestamptz to *time.Time (nil when not valid).
func tsPtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

func (s *Service) encrypt(tenantID, userID uuid.UUID, provider, purpose, plaintext string) (ciphertext, nonce []byte, err error) {
	resource := userID.String() + ":" + provider
	return s.box.Seal(tenantID, purpose, resource, []byte(plaintext))
}

func (s *Service) decrypt(tenantID, userID uuid.UUID, provider, purpose string, ciphertext, nonce []byte) (string, error) {
	resource := userID.String() + ":" + provider
	pt, err := s.box.Open(tenantID, purpose, resource, ciphertext, nonce)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// --- provider registration (admin) ---

// RegisterProviderInput is what RegisterProvider takes.
type RegisterProviderInput struct {
	Provider     string `json:"provider" validate:"required"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	AuthorizeURL string `json:"authorize_url" validate:"required,url"`
	TokenURL     string `json:"token_url" validate:"required,url"`
	Scopes       string `json:"scopes"`
}

// RegisterProvider stores the tenant's settings for an OAuth provider.
func (s *Service) RegisterProvider(ctx context.Context, tenantID uuid.UUID, in RegisterProviderInput) (*Provider, error) {
	if _, err := s.egress.ValidateHTTPURL(in.AuthorizeURL); err != nil {
		return nil, errs.ErrTokenVaultProviderAuthorizeInvalid
	}
	if _, err := s.egress.ValidateHTTPURL(in.TokenURL); err != nil {
		return nil, errs.ErrTokenVaultProviderAuthorizeInvalid
	}
	ct, nonce, err := s.box.Seal(tenantID, "token-vault-provider", in.Provider, []byte(in.ClientSecret))
	if err != nil {
		return nil, err
	}
	var provider Provider
	err = s.pool.QueryRow(ctx, `
		INSERT INTO tenant.token_vault_providers
		    (tenant_id, provider, client_id, client_secret, client_secret_ct,
		     client_secret_nonce, encryption_version, authorize_url, token_url, scopes)
		VALUES ($1, $2, $3, '', $4, $5, 1, $6, $7, $8)
		ON CONFLICT (tenant_id, provider) DO UPDATE SET
		    client_id = EXCLUDED.client_id,
		    client_secret = '',
		    client_secret_ct = EXCLUDED.client_secret_ct,
		    client_secret_nonce = EXCLUDED.client_secret_nonce,
		    encryption_version = 1,
		    authorize_url = EXCLUDED.authorize_url,
		    token_url = EXCLUDED.token_url,
		    scopes = EXCLUDED.scopes,
		    updated_at = NOW()
		RETURNING id, provider, client_id, authorize_url, token_url, scopes, created_at, updated_at
	`, tenantID, in.Provider, in.ClientID, ct, nonce, in.AuthorizeURL, in.TokenURL, in.Scopes).Scan(
		&provider.ID, &provider.Provider, &provider.ClientID, &provider.AuthorizeURL,
		&provider.TokenURL, &provider.Scopes, &provider.CreatedAt, &provider.UpdatedAt,
	)
	return &provider, err
}

// ListProviders returns the tenant's OAuth providers.
func (s *Service) ListProviders(ctx context.Context, tenantID uuid.UUID) ([]Provider, error) {
	rows, err := s.q.ListProviders(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(rows))
	for _, row := range rows {
		out = append(out, Provider{
			ID: row.ID, Provider: row.Provider, ClientID: row.ClientID,
			AuthorizeURL: row.AuthorizeUrl, TokenURL: row.TokenUrl, Scopes: row.Scopes,
			CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		})
	}
	return out, nil
}

// DeleteProvider removes the tenant's settings for an OAuth provider.
func (s *Service) DeleteProvider(ctx context.Context, tenantID uuid.UUID, provider string) error {
	n, err := s.q.DeleteProvider(ctx, dbgen.DeleteProviderParams{TenantID: tenantID, Provider: provider})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrTokenVaultProviderNotFound
	}
	return nil
}

func (s *Service) providerConfig(ctx context.Context, tenantID uuid.UUID, provider string) (clientID, clientSecret, authorizeURL, tokenURL, scopes string, err error) {
	var legacy string
	var ciphertext, nonce []byte
	err = s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret, client_secret_ct, client_secret_nonce,
		       authorize_url, token_url, scopes
		FROM tenant.token_vault_providers
		WHERE tenant_id = $1 AND provider = $2
	`, tenantID, provider).Scan(&clientID, &legacy, &ciphertext, &nonce, &authorizeURL, &tokenURL, &scopes)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", "", errs.ErrTokenVaultProviderNotFound
	}
	if err != nil {
		return "", "", "", "", "", err
	}
	if len(ciphertext) > 0 {
		plain, openErr := s.box.Open(tenantID, "token-vault-provider", provider, ciphertext, nonce)
		return clientID, string(plain), authorizeURL, tokenURL, scopes, openErr
	}
	if legacy == "" {
		return "", "", "", "", "", errs.ErrTokenVaultProviderNotFound
	}
	ct, newNonce, sealErr := s.box.Seal(tenantID, "token-vault-provider", provider, []byte(legacy))
	if sealErr != nil {
		return "", "", "", "", "", sealErr
	}
	if _, updateErr := s.pool.Exec(ctx, `
		UPDATE tenant.token_vault_providers
		SET client_secret = '', client_secret_ct = $3, client_secret_nonce = $4,
		    encryption_version = 1, updated_at = NOW()
		WHERE tenant_id = $1 AND provider = $2 AND client_secret_ct IS NULL
	`, tenantID, provider, ct, newNonce); updateErr != nil {
		return "", "", "", "", "", updateErr
	}
	return clientID, legacy, authorizeURL, tokenURL, scopes, nil
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
	if err := s.q.InsertConnectState(ctx, dbgen.InsertConnectStateParams{
		State:     state,
		TenantID:  tenantID,
		UserID:    userID,
		Provider:  provider,
		ExpiresAt: time.Now().UTC().Add(connectStateTTL),
	}); err != nil {
		return "", err
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", errs.ErrTokenVaultProviderAuthorizeInvalid
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

// oauthTokenResponse is the standard OAuth 2.0 token response (RFC 6749 §5.1).
// ExpiresIn is any because some providers send it as a numeric string.
type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    any    `json:"expires_in"`
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
	cs, err := s.q.DeleteConnectState(ctx, state)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrTokenVaultConnectStateInvalid
	}
	if err != nil {
		return err
	}
	tenantID, userID, provider := cs.TenantID, cs.UserID, cs.Provider
	if time.Now().After(cs.ExpiresAt) {
		return errs.ErrTokenVaultConnectExpired
	}

	clientID, clientSecret, _, tokenURL, _, err := s.providerConfig(ctx, tenantID, provider)
	if err != nil {
		return err
	}
	tok, err := s.exchange(ctx, tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL(base)},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	if err != nil {
		return err
	}
	return s.storeGrant(ctx, tenantID, userID, provider, tok)
}

func (s *Service) storeGrant(ctx context.Context, tenantID, userID uuid.UUID, provider string, tok *oauthTokenResponse) error {
	accessCT, accessNonce, err := s.encrypt(tenantID, userID, provider, "token-vault-access", tok.AccessToken)
	if err != nil {
		return err
	}
	// nil []byte == SQL NULL for nullable bytea columns.
	var refreshCT, refreshNonce []byte
	if tok.RefreshToken != "" {
		ct, nonce, err := s.encrypt(tenantID, userID, provider, "token-vault-refresh", tok.RefreshToken)
		if err != nil {
			return err
		}
		refreshCT, refreshNonce = ct, nonce
	}
	var expiresAt pgtype.Timestamptz
	if secs := tok.expiresInSeconds(); secs > 0 {
		expiresAt = pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Duration(secs) * time.Second), Valid: true}
	}
	tokenType := tok.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	var scopeArg *string
	if tok.Scope != "" {
		scopeArg = &tok.Scope
	}
	return s.q.UpsertTokenGrant(ctx, dbgen.UpsertTokenGrantParams{
		TenantID:          tenantID,
		UserID:            userID,
		Provider:          provider,
		AccessTokenCt:     accessCT,
		AccessTokenNonce:  accessNonce,
		RefreshTokenCt:    refreshCT,
		RefreshTokenNonce: refreshNonce,
		TokenType:         tokenType,
		Scope:             scopeArg,
		ExpiresAt:         expiresAt,
	})
}

// exchange POSTs a form-encoded OAuth2 token request and parses the response.
// Shared by the initial code exchange and refresh.
func (s *Service) exchange(ctx context.Context, tokenURL string, form url.Values) (*oauthTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode())) // #nosec G704 -- token URL checked by the egress policy on save
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req) // #nosec G704 -- egress-guarded client
	if err != nil {
		return nil, errs.ErrTokenVaultTokenExchangeFailed.Wrap(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errs.ErrTokenVaultTokenExchangeFailed
	}
	var tok oauthTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, errs.ErrTokenVaultTokenExchangeFailed.Wrap(err)
	}
	if tok.AccessToken == "" {
		return nil, errs.ErrTokenVaultTokenExchangeFailed
	}
	return &tok, nil
}

// --- runtime use ---

// GetAccessToken returns a live access token for (tenantID, userID, provider),
// transparently refreshing it first if it's expired (or about to be) and a
// refresh token is on file. The raw refresh token is never returned to the
// caller — only ever used internally to mint a new access token.
func (s *Service) GetAccessToken(ctx context.Context, tenantID, userID uuid.UUID, provider string) (string, error) {
	grant, err := s.q.GetTokenGrant(ctx, dbgen.GetTokenGrantParams{TenantID: tenantID, UserID: userID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrTokenVaultGrantNotFound
	}
	if err != nil {
		return "", err
	}
	accessCT, accessNonce := grant.AccessTokenCt, grant.AccessTokenNonce
	refreshCT, refreshNonce := grant.RefreshTokenCt, grant.RefreshTokenNonce
	expiresAt := tsPtr(grant.ExpiresAt)

	if expiresAt == nil || time.Now().Before(expiresAt.Add(-expirySkew)) {
		return s.decrypt(tenantID, userID, provider, "token-vault-access", accessCT, accessNonce)
	}
	if refreshCT == nil {
		// Expired with no refresh token on file — the caller must reconnect.
		return "", errs.ErrTokenVaultTokenExpired
	}
	refreshToken, err := s.decrypt(tenantID, userID, provider, "token-vault-refresh", refreshCT, refreshNonce)
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

// ListGrants returns the providers the user has connected, without their
// tokens.
func (s *Service) ListGrants(ctx context.Context, tenantID, userID uuid.UUID) ([]GrantMeta, error) {
	rows, err := s.q.ListGrants(ctx, dbgen.ListGrantsParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]GrantMeta, 0, len(rows))
	for _, row := range rows {
		out = append(out, GrantMeta{
			Provider:          row.Provider,
			ExternalAccountID: row.ExternalAccountID,
			Scope:             row.Scope,
			ExpiresAt:         tsPtr(row.ExpiresAt),
			CreatedAt:         row.CreatedAt,
			UpdatedAt:         row.UpdatedAt,
		})
	}
	return out, nil
}

// Disconnect deletes the user's stored tokens for a provider.
func (s *Service) Disconnect(ctx context.Context, tenantID, userID uuid.UUID, provider string) error {
	n, err := s.q.DeleteGrant(ctx, dbgen.DeleteGrantParams{TenantID: tenantID, UserID: userID, Provider: provider})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrTokenVaultGrantNotFound
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

// --- HTTP ---

// Handler serves the token vault. PublicBaseURL is this API's public origin,
// or "" to build OAuth callback URLs from the request's Host.
type Handler struct {
	Service       *Service
	PublicBaseURL string
}

// Mount registers the token vault routes on r.
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

func (h *Handler) registerProvider(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
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
	tenantID, err := httpx.PathTenant(r)
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
	tenantID, err := httpx.PathTenant(r)
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
	authorizeURL, err := h.Service.BeginConnect(r.Context(), tenantID, userID, chi.URLParam(r, "provider"), httpx.PublicOrigin(r, h.PublicBaseURL))
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
	if err := h.Service.FinishConnect(r.Context(), state, code, httpx.PublicOrigin(r, h.PublicBaseURL)); err != nil {
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
	_, _ = w.Write([]byte(`<!doctype html><html><body><p>Connection failed: ` + htmlEscape(errMsg) + `</p></body></html>`)) // #nosec G705 -- errMsg is HTML-escaped
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

// getAccessToken returns a live access token, refreshed if needed, only to the
// person who connected the account, signed in themselves (any other credential
// is refused and recorded) and holding vault:<provider> or vault:read. Each
// read is audited.
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
	provider := chi.URLParam(r, "provider")
	// A connected account's raw token goes only to the person who connected
	// it, signed in themselves. An API key, service principal, agent or
	// application token carries a user id it was given, not one it proved, so
	// it is refused, and the attempt is recorded as that credential.
	if !signedInPerson(p) {
		h.recordAccessRefused(r, p, tenantID, provider)
		httpx.WriteError(w, r, errs.ErrTokenVaultPeopleOnly)
		return
	}
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !hasVaultScope(p.Scopes, provider) {
		httpx.WriteError(w, r, errs.ErrTokenVaultScopeRequired)
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
			ActorType:    "user",
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

// signedInPerson reports whether p is a person's own session: not an API key,
// service principal or agent, and not a token issued to an application.
func signedInPerson(p *httpx.Principal) bool {
	return (p.ActorType == "" || p.ActorType == "user") && p.UserID != nil && p.SessionID != nil && p.ClientID == ""
}

// recordAccessRefused audits a refused token read under the credential that
// tried, never under the user id that credential carries.
func (h *Handler) recordAccessRefused(r *http.Request, p *httpx.Principal, tenantID uuid.UUID, provider string) {
	ctx := r.Context()
	tx, err := h.Service.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	meta := map[string]any{"provider": provider, "credential_id": p.Subject}
	if p.UserID != nil {
		meta["target_user_id"] = p.UserID.String()
	}
	if p.ClientID != "" {
		meta["client_id"] = p.ClientID
	}
	actorType := p.ActorType
	if actorType == "" {
		actorType = "user"
	}
	if audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorType:    actorType,
		Action:       "vault.tokens.access_refused",
		ResourceType: "token_vault_grant",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	}) == nil {
		_ = tx.Commit(ctx)
	}
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
