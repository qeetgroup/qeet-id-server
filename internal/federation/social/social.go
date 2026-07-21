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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q          *dbgen.Queries
	auth       *auth.Service
	appBaseURL string
	oauth      *oauthClient
}

func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string) *Service {
	return &Service{
		pool:       pool,
		q:          dbgen.New(pool),
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
	r, err := s.q.UpsertSocialProvider(ctx, dbgen.UpsertSocialProviderParams{
		TenantID:     in.TenantID,
		Provider:     in.Provider,
		ClientID:     in.ClientID,
		ClientSecret: in.ClientSecret,
		DiscoveryUrl: in.DiscoveryURL,
	})
	if err != nil {
		return nil, err
	}
	p := Provider{
		ID:           r.ID,
		TenantID:     r.TenantID,
		Provider:     r.Provider,
		ClientID:     r.ClientID,
		DiscoveryURL: r.DiscoveryUrl,
		Enabled:      r.Enabled,
		CreatedAt:    r.CreatedAt,
	}
	return &p, nil
}

func (s *Service) ListProviders(ctx context.Context, tenantID uuid.UUID) ([]Provider, error) {
	rows, err := s.q.ListSocialProviders(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, len(rows))
	for i, r := range rows {
		out[i] = Provider{
			ID:           r.ID,
			TenantID:     r.TenantID,
			Provider:     r.Provider,
			ClientID:     r.ClientID,
			DiscoveryURL: r.DiscoveryUrl,
			Enabled:      r.Enabled,
			CreatedAt:    r.CreatedAt,
		}
	}
	return out, nil
}

func (s *Service) ListIdentities(ctx context.Context, userID, tenantID uuid.UUID) ([]ExternalIdentity, error) {
	// Tenant-scoped so one tenant can't read another's linked identities;
	// the deleted_at join keeps soft-deleted users out of admin lookups.
	rows, err := s.q.ListExternalIdentities(ctx, dbgen.ListExternalIdentitiesParams{
		UserID:   userID,
		TenantID: tenantID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ExternalIdentity, len(rows))
	for i, r := range rows {
		out[i] = ExternalIdentity{
			ID:       r.ID,
			UserID:   r.UserID,
			TenantID: r.TenantID,
			Provider: r.Provider,
			Subject:  r.Subject,
			Email:    r.Email,
			LinkedAt: r.LinkedAt,
		}
	}
	return out, nil
}

// Unlink is tenant-scoped so an identity can only be removed within its tenant.
func (s *Service) Unlink(ctx context.Context, id, tenantID uuid.UUID) error {
	n, err := s.q.DeleteExternalIdentity(ctx, dbgen.DeleteExternalIdentityParams{
		ID:       id,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
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
	id, err := s.q.GetTenantIDBySlug(ctx, ref)
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
	r, err := s.q.LoadSocialProvider(ctx, dbgen.LoadSocialProviderParams{
		TenantID: tenantID,
		Provider: provider,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return pc, errs.ErrNotFound.WithDetail("provider not configured")
	}
	if err != nil {
		return pc, err
	}
	if !r.Enabled {
		return pc, errs.ErrBadRequest.WithDetail("provider disabled")
	}
	if r.DiscoveryUrl == nil || *r.DiscoveryUrl == "" {
		return pc, errs.ErrBadRequest.WithDetail("provider has no discovery_url (OIDC discovery required)")
	}
	pc.clientID = r.ClientID
	pc.clientSecret = r.ClientSecret
	pc.discoveryURL = *r.DiscoveryUrl
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
	if err := s.q.InsertSocialOAuthState(ctx, dbgen.InsertSocialOAuthStateParams{
		StateHash:    stateHash,
		TenantID:     tenantID,
		Provider:     provider,
		CodeVerifier: verifier,
		RedirectUri:  redirectURI,
		ReturnTo:     returnTo,
		ExpiresAt:    time.Now().UTC().Add(socialStateTTL),
	}); err != nil {
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

	// Single-use: delete the state row as we read it.
	st, err := s.q.ConsumeSocialOAuthState(ctx, stateHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("invalid or used state")
	}
	if err != nil {
		return nil, err
	}
	if st.Provider != provider {
		return nil, errs.ErrBadRequest.WithDetail("provider mismatch")
	}
	if time.Now().After(st.ExpiresAt) {
		return nil, errs.ErrBadRequest.WithDetail("state expired")
	}

	pc, err := s.loadProvider(ctx, st.TenantID, provider)
	if err != nil {
		return nil, err
	}
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("provider discovery failed")
	}
	accessToken, err := s.oauth.exchange(ctx, doc, pc.clientID, pc.clientSecret, code, st.RedirectUri, st.CodeVerifier)
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

	userID, err := s.findOrCreateUser(ctx, st.TenantID, provider, ui)
	if err != nil {
		return nil, err
	}

	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	if err := s.q.InsertSocialLoginCode(ctx, dbgen.InsertSocialLoginCodeParams{
		CodeHash:  codeHash,
		UserID:    userID,
		TenantID:  st.TenantID,
		ExpiresAt: time.Now().UTC().Add(socialCodeTTL),
	}); err != nil {
		return nil, err
	}
	return &CallbackResult{Code: rawCode, ReturnTo: st.ReturnTo, UserID: userID, TenantID: st.TenantID}, nil
}

// EnabledProviderNames returns the names of a tenant's enabled social providers
// (for the hosted login app to render buttons). Satisfies oidc.ProviderLister.
func (s *Service) EnabledProviderNames(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return s.q.EnabledSocialProviderNames(ctx, tenantID)
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

	q := s.q.WithTx(tx)

	userID, err := q.GetExternalIdentityUser(ctx, dbgen.GetExternalIdentityUserParams{
		TenantID: tenantID,
		Provider: provider,
		Subject:  ui.Subject,
	})
	if err == nil {
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	// No linked identity yet: reuse a user with the same (globally-unique)
	// email, else create one.
	userID, err = q.GetUserByEmail(ctx, ui.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		var displayName *string
		if ui.Name != "" {
			displayName = &ui.Name
		}
		userID, err = q.InsertUserWithEmail(ctx, dbgen.InsertUserWithEmailParams{
			TenantID:    pgtype.UUID{Bytes: tenantID, Valid: true},
			Email:       ui.Email,
			DisplayName: displayName,
		})
		if err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}

	var emailPtr *string
	if ui.Email != "" {
		emailPtr = &ui.Email
	}
	if err := q.LinkExternalIdentity(ctx, dbgen.LinkExternalIdentityParams{
		UserID:   userID,
		TenantID: tenantID,
		Provider: provider,
		Subject:  ui.Subject,
		Email:    emailPtr,
	}); err != nil {
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

	q := s.q.WithTx(tx)

	row, err := q.ConsumeSocialLoginCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid code")
	}
	if err != nil {
		return nil, err
	}
	if row.UsedAt.Valid {
		return nil, errs.ErrUnauthorized.WithDetail("code already used")
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("code expired")
	}
	if err := q.MarkSocialLoginCodeUsed(ctx, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, row.UserID, row.TenantID, ip, ua, "social")
}

type Handler struct {
	Service *Service
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only); set
	// from SERVICE_ENV != "dev".
	CookieSecure bool
	// LoginBaseURL is the hosted login app origin (qeetid-login). Browser-facing
	// ceremony failures redirect here with a generic error code rather than
	// dumping a JSON error body at a top-level redirect.
	LoginBaseURL string
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

// redirectSocialError sends a failed browser-facing social ceremony back to the
// hosted login app with a generic error code, rather than rendering a raw JSON
// error body at a top-level redirect. The underlying detail is intentionally
// not leaked to the URL; the structured error is still logged server-side. The
// return_to (present on start, encoded in state on callback) is preserved when
// available so the user can retry into the same app.
func (h *Handler) redirectSocialError(w http.ResponseWriter, r *http.Request, err error) {
	if h.LoginBaseURL == "" {
		// No hosted login app configured — fall back to the JSON error.
		httpx.WriteError(w, r, err)
		return
	}
	q := url.Values{"error": {"social"}}
	if rt := r.URL.Query().Get("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, h.LoginBaseURL+"/login?"+q.Encode(), http.StatusFound)
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
		h.redirectSocialError(w, r, err)
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
		h.redirectSocialError(w, r, err)
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
