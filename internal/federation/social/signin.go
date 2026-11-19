package social

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oauthstate"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	socialStateTTL = 10 * time.Minute
	socialCodeTTL  = 2 * time.Minute
	socialScopes   = "openid email profile"
)

// providerConfig is one provider's settings. kind is "oidc" when discoveryURL
// drives the generic OIDC flow, or the adapter of github.go, apple.go or
// adapters.go. Only Apple uses teamID, keyID and privateKey, to sign its
// short-lived client secret.
type providerConfig struct {
	clientID     string
	clientSecret string
	discoveryURL string
	kind         string
	teamID       string
	keyID        string
	privateKey   string
}

// resolveOrganization maps an organization id (uuid) or slug to an organization id.
func (s *Service) resolveOrganization(ctx context.Context, ref string) (uuid.UUID, error) {
	if ref == "" {
		return uuid.Nil, ErrOrganizationRequired
	}
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	id, err := s.q.GetOrganizationIDBySlug(ctx, ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrOrganizationNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// loadProvider returns an organization's enabled provider config: discovery-based for
// OpenID Connect, or for the adapter the provider's name picks.
func (s *Service) loadProvider(ctx context.Context, organizationID uuid.UUID, provider string) (providerConfig, error) {
	var pc providerConfig
	row, err := s.q.GetSocialProviderConfig(ctx, dbgen.GetSocialProviderConfigParams{OrganizationID: organizationID, Provider: provider})
	enabled, clientID, discoveryURL, teamID, keyID, ciphertext, nonce := row.Enabled, row.ClientID, row.DiscoveryUrl, row.AppleTeamID, row.AppleKeyID, row.ClientSecretCt, row.ClientSecretNonce
	if errors.Is(err, pgx.ErrNoRows) {
		return pc, ErrProviderNotConfigured
	}
	if err != nil {
		return pc, err
	}
	// Switched off reads exactly like never set up: an unauthenticated
	// caller cannot tell an organization has switched a provider off.
	if !enabled {
		return pc, ErrProviderNotConfigured
	}
	pc.kind = adapterKind(provider)
	if pc.kind == kindOIDC {
		if discoveryURL == nil || *discoveryURL == "" {
			return pc, ErrProviderNoDiscovery
		}
		pc.discoveryURL = *discoveryURL
	}
	if pc.kind == kindApple {
		if teamID == nil || keyID == nil {
			return pc, ErrProviderNotConfigured
		}
		pc.teamID, pc.keyID = *teamID, *keyID
	}
	pc.clientID = clientID
	plain, err := s.box.Open(organizationID, "social-provider", provider, ciphertext, nonce)
	if err != nil {
		return pc, err
	}
	pc.clientSecret = string(plain)
	if pc.kind == kindApple {
		pc.privateKey = pc.clientSecret
	}
	return pc, nil
}

// BeginLogin resolves the organization + provider, persists CSRF state with a PKCE
// verifier, and returns the upstream authorization URL to redirect the user to.
func (s *Service) BeginLogin(ctx context.Context, provider, organizationRef, redirectURI, returnTo string) (string, error) {
	// Validate before anything is persisted, so a rejected value never reaches
	// the callback that would redirect to it.
	if err := s.validateReturnTo(returnTo); err != nil {
		return "", err
	}
	organizationID, err := s.resolveOrganization(ctx, organizationRef)
	if err != nil {
		return "", err
	}
	pc, err := s.loadProvider(ctx, organizationID, provider)
	if err != nil {
		return "", err
	}
	var doc oidcrp.Discovery
	if pc.kind == kindOIDC {
		if doc, err = s.oidc.Discover(ctx, pc.discoveryURL); err != nil {
			return "", ErrDiscoveryFailed.Wrap(err)
		}
	}
	verifier, challenge, nonce, nonceHash, err := ceremonySecrets(pc.kind)
	if err != nil {
		return "", err
	}
	state, err := oauthstate.Save(ctx, s.pool, oauthstate.State{
		Kind:           oauthstate.KindSocial,
		OrganizationID: organizationID,
		Provider:       provider,
		CodeVerifier:   verifier,
		NonceHash:      nonceHash,
		RedirectURI:    redirectURI,
		ReturnTo:       returnTo,
	}, socialStateTTL)
	if err != nil {
		return "", err
	}
	return s.authorizeURL(pc, doc, redirectURI, state, challenge, nonce), nil
}

// ceremonySecrets returns a new PKCE verifier and its S256 challenge, and, for
// a provider whose ID token signs the person in (OpenID Connect, Apple), a new
// nonce and its hash.
func ceremonySecrets(kind string) (verifier, challenge, nonce, nonceHash string, err error) {
	if verifier, challenge, err = codes.URLToken(); err != nil {
		return "", "", "", "", err
	}
	if kind == kindOIDC || kind == kindApple {
		if nonce, nonceHash, err = codes.URLToken(); err != nil {
			return "", "", "", "", err
		}
	}
	return verifier, challenge, nonce, nonceHash, nil
}

// authorizeURL is where the browser starts a sign-in with pc's provider (doc
// is an OpenID Connect provider's discovery document): with the state, and
// the PKCE challenge and the nonce where the provider takes them.
func (s *Service) authorizeURL(pc providerConfig, doc oidcrp.Discovery, redirectURI, state, challenge, nonce string) string {
	switch pc.kind {
	case kindGitHub:
		// GitHub OAuth Apps take no PKCE.
		return githubAuthorizeURL + "?" + url.Values{
			"client_id": {pc.clientID}, "redirect_uri": {redirectURI}, "scope": {githubScopes}, "state": {state},
		}.Encode()
	case kindApple:
		// Asking for the name and address makes Apple answer by form_post.
		return appleAuthorizeURL + "?" + url.Values{
			"response_type": {"code"}, "response_mode": {"form_post"}, "client_id": {pc.clientID},
			"redirect_uri": {redirectURI}, "scope": {appleScopes}, "state": {state}, "nonce": {nonce},
		}.Encode()
	case kindFacebook, kindX, kindDiscord:
		return s.oauth.oauth2AuthorizeURL(pc.kind, pc.clientID, redirectURI, state, challenge)
	}
	return oidcrp.AuthorizeURL(doc.AuthorizationEndpoint, url.Values{
		"response_type":         {"code"},
		"client_id":             {pc.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {socialScopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
}

// CallbackResult is a successful callback's outcome: a one-time code the SPA
// trades for a session and, for the hosted flow, the return_to and the user and
// organization to set the SSO cookie for.
type CallbackResult struct {
	Code           string
	ReturnTo       string
	UserID         uuid.UUID
	OrganizationID uuid.UUID
}

// stateRefusals are the errors a social sign-in's state is refused with.
var stateRefusals = oauthstate.Refusals{Invalid: ErrStateInvalid, Expired: ErrStateExpired}

// CompleteCallback consumes the state, exchanges the code, finds or creates the user and linked
// identity, and returns a one-time code the SPA trades for a session. Without startedHere it fails with
// ErrSocialBrowserMismatch; that, a closed organization and a domain that requires single sign-on
// (errs.ErrAuthSSORequired) still return the result's ReturnTo. ip and ua are the browser's, for the
// record of a refusal.
func (s *Service) CompleteCallback(ctx context.Context, provider, state, code string, startedHere bool, ip, ua string) (*CallbackResult, error) {
	if state == "" || code == "" {
		return nil, ErrCallbackParamsMissing
	}
	st, err := oauthstate.Take(ctx, s.pool, oauthstate.KindSocial, state, uuid.Nil, stateRefusals)
	if err != nil {
		return nil, err
	}
	if st.Provider != provider {
		return nil, ErrProviderMismatch
	}
	if !startedHere {
		return &CallbackResult{ReturnTo: st.ReturnTo, OrganizationID: st.OrganizationID}, ErrBrowserMismatch
	}

	pc, err := s.loadProvider(ctx, st.OrganizationID, provider)
	if err != nil {
		return nil, err
	}
	ui, err := s.signedIn(ctx, pc, code, st.RedirectURI, st.CodeVerifier, st.NonceHash)
	if err != nil {
		return nil, err
	}
	userID, err := s.signInAccount(ctx, st.OrganizationID, provider, ui, audit.Actor{Type: "social", IP: ip, UserAgent: ua, RequestID: middleware.GetReqID(ctx)})
	if errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) {
		// The return_to comes back with the refusal so the person lands on the
		// application's sign-in page, told why, rather than losing their way.
		if aerr := s.recordSignUpRefused(ctx, st.OrganizationID, provider, ui); aerr != nil {
			return nil, aerr
		}
		return &CallbackResult{ReturnTo: st.ReturnTo, OrganizationID: st.OrganizationID}, err
	}
	if err == nil {
		// An account already linked signs in no more once its organization requires
		// single sign-on on its domain (adoption and sign-up were refused above).
		err = s.refuseCapturedAccount(ctx, userID)
	}
	if errors.Is(err, errs.ErrAuthSSORequired) {
		// So does that refusal, so the person can go on through the
		// organization's single sign-on instead.
		return &CallbackResult{ReturnTo: st.ReturnTo, OrganizationID: st.OrganizationID}, err
	}
	if err != nil {
		return nil, err
	}

	// A suspended or deleted account gets no code to sign in with.
	if err := s.auth.CheckSignInAccount(ctx, userID, st.OrganizationID, "social", ip, ua); err != nil {
		return nil, err
	}
	rawCode, err := logincode.Issue(ctx, s.pool, logincode.Code{
		Kind: logincode.KindSocial, UserID: userID, OrganizationID: st.OrganizationID, Provider: provider,
	}, socialCodeTTL)
	if err != nil {
		return nil, err
	}
	return &CallbackResult{Code: rawCode, ReturnTo: st.ReturnTo, UserID: userID, OrganizationID: st.OrganizationID}, nil
}

// signedIn trades code with pc's provider and returns who signed in: through
// its verified ID token and userinfo for OpenID Connect, or the provider's
// adapter. nonceHash is the hash of the nonce the sign-in sent.
func (s *Service) signedIn(ctx context.Context, pc providerConfig, code, redirectURI, verifier, nonceHash string) (userInfo, error) {
	switch pc.kind {
	case kindGitHub:
		accessToken, err := s.oauth.githubExchange(ctx, pc.clientID, pc.clientSecret, code, redirectURI)
		if err != nil {
			return userInfo{}, ErrTokenExchangeFailed.Wrap(err)
		}
		ui, err := s.oauth.githubUserinfo(ctx, accessToken)
		if err != nil {
			return userInfo{}, ErrUserinfoFailed.Wrap(err)
		}
		return ui, nil
	case kindApple:
		if nonceHash == "" {
			return userInfo{}, ErrStateInvalid
		}
		secret, err := appleClientSecret(pc.clientID, pc.teamID, pc.keyID, pc.privateKey)
		if err != nil {
			return userInfo{}, ErrTokenExchangeFailed.Wrap(errors.Join(errAppleKey, err))
		}
		ui, err := s.appleSignIn(ctx, pc.clientID, secret, code, redirectURI, nonceHash)
		if err != nil {
			return userInfo{}, ErrTokenExchangeFailed.Wrap(err)
		}
		return ui, nil
	case kindFacebook, kindX, kindDiscord:
		accessToken, err := s.oauth.oauth2Exchange(ctx, pc.kind, pc.clientID, pc.clientSecret, code, redirectURI, verifier)
		if err != nil {
			return userInfo{}, ErrTokenExchangeFailed.Wrap(err)
		}
		ui, err := s.oauth.oauth2Userinfo(ctx, pc.kind, accessToken)
		if err != nil {
			return userInfo{}, ErrUserinfoFailed.Wrap(err)
		}
		return ui, nil
	}
	if nonceHash == "" {
		return userInfo{}, ErrStateInvalid
	}
	doc, err := s.oidc.Discover(ctx, pc.discoveryURL)
	if err != nil {
		return userInfo{}, ErrDiscoveryFailed.Wrap(err)
	}
	tokens, err := s.oidc.Exchange(ctx, doc, oidcrp.Credentials{ClientID: pc.clientID, ClientSecret: pc.clientSecret}, code, redirectURI, verifier)
	if err == nil && (tokens.IDToken == "" || tokens.AccessToken == "") {
		err = errors.New("token endpoint: no id_token or access_token")
	}
	if err != nil {
		return userInfo{}, ErrTokenExchangeFailed.Wrap(err)
	}
	// The ID token proves the sign-in is this one's, from the provider's
	// issuer, for this client; userinfo must be about the same subject.
	claims, err := s.oidc.VerifyIDToken(ctx, tokens.IDToken, doc.JWKSURI, oidcrp.RulesFor(doc, pc.clientID, nonceHash))
	if err != nil {
		return userInfo{}, ErrTokenExchangeFailed.Wrap(err)
	}
	var ui userInfo
	if err := s.oidc.Userinfo(ctx, doc, tokens.AccessToken, &ui); err != nil {
		return userInfo{}, ErrUserinfoFailed.Wrap(err)
	}
	if sub, _ := claims["sub"].(string); ui.Subject == "" || ui.Subject != sub {
		return userInfo{}, ErrUserinfoFailed.Wrap(errors.New("userinfo names another subject than the id_token"))
	}
	return ui, nil
}

// EnabledProviderNames returns the names of an organization's enabled social providers
// (for the hosted login app to render buttons). Satisfies oidc.ProviderLister.
func (s *Service) EnabledProviderNames(ctx context.Context, organizationID uuid.UUID) ([]string, error) {
	return s.q.EnabledSocialProviderNames(ctx, organizationID)
}

// BeginLoginSession signs a social-authenticated user in to the hosted login
// for organizationID, so social login can drive the OAuth authorize/consent flow: the
// SSO session cookie value, or the second-factor challenge to complete first
// (see authentication.Service.BeginSocialLoginSession).
func (s *Service) BeginLoginSession(ctx context.Context, userID, organizationID uuid.UUID, ip, ua, trustedToken, country string) (*authentication.LoginSessionResult, error) {
	return s.auth.BeginSocialLoginSession(ctx, userID, organizationID, ip, ua, trustedToken, country)
}

// CheckHostedSignIn asks the organization's address rules whether the browser
// at ip may finish a hosted social sign-in to it.
func (s *Service) CheckHostedSignIn(ctx context.Context, organizationID, userID uuid.UUID, ip string) error {
	return s.auth.CheckSignInAddress(ctx, organizationID, userID, ip, "hosted_social")
}

// callbackURL returns the public callback URL the upstream provider must
// redirect back to; it must match between start and the token exchange.
func (h *Handler) callbackURL(r *http.Request, provider string) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL) + "/v1/social/" + provider + "/callback"
}

// binding ties a sign-in begun at start to the browser that began it, so the
// callback completes it only there. SameSite=None so Apple's cross-site
// form_post callback carries it — Lax where the cookie can't be Secure (dev).
func (h *Handler) binding() httpx.BindingCookie {
	sameSite := http.SameSiteNoneMode
	if !h.CookieSecure {
		sameSite = http.SameSiteLaxMode
	}
	return httpx.BindingCookie{Name: "qe_social", Secure: h.CookieSecure, SameSite: sameSite, MaxAge: socialStateTTL}
}

// stateOf is the state a provider authorization URL carries.
func stateOf(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}

// start redirects the browser to the provider and gives it the binding the
// callback checks. ?organization=<slug> or ?organization_id=<uuid> names the organization
// (none means the console's platform sign-in); ?return_to opts into the hosted
// flow.
func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	organizationRef := r.URL.Query().Get("organization")
	if organizationRef == "" {
		organizationRef = r.URL.Query().Get("organization_id")
	}
	// No organization → platform (organization-less) console flow. ?intent=signup permits
	// just-in-time account creation; anything else (sign-in) requires an existing
	// account, so a "sign in with Google" can't silently create one.
	if organizationRef == "" {
		allowCreate := r.URL.Query().Get("intent") == "signup"
		authURL, err := h.Service.BeginPlatformLogin(r.Context(), provider, h.callbackURL(r, provider), allowCreate)
		if err != nil {
			h.redirectSocialError(w, r, err)
			return
		}
		h.binding().Add(w, r, stateOf(authURL))
		http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- operator-configured provider endpoint
		return
	}
	authURL, err := h.Service.BeginLogin(r.Context(), provider, organizationRef, h.callbackURL(r, provider), r.URL.Query().Get("return_to"))
	if err != nil {
		h.redirectSocialError(w, r, err)
		return
	}
	h.binding().Add(w, r, stateOf(authURL))
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- authorization_endpoint checked by oidcrp.ValidAuthorizationEndpoint
}

// callback handles the provider's redirect. The hosted flow (return_to set) sets
// the SSO cookie and returns to return_to; otherwise the SPA gets a one-time
// code, never tokens in the URL. A sign-in completes only in the browser start
// gave the binding to.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	// Apple uses response_mode=form_post (params in the POST body); the other
	// providers use a GET query. r.FormValue reads whichever applies.
	if r.Method == http.MethodPost {
		if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
			h.redirectSocialError(w, r, err)
			return
		}
	}
	state, code := r.FormValue("state"), r.FormValue("code")
	startedHere := h.binding().Holds(r, state)

	if h.platformCallbackAnswered(w, r, provider, state, code, startedHere) {
		return
	}

	res, err := h.Service.CompleteCallback(r.Context(), provider, state, code, startedHere, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		// A closed organization, a sign-in begun in another browser or a
		// domain that requires single sign-on is not a provider failure: say
		// so, and keep the way back to the application (validated when the
		// sign-in began). The callback's own query carries no return_to.
		returnTo := ""
		if res != nil {
			returnTo = res.ReturnTo
		}
		h.redirectToLogin(w, r, err, returnTo)
		return
	}
	h.binding().Remove(w, r, state)
	if res.ReturnTo != "" {
		h.finishHostedSignIn(w, r, res)
		return
	}
	target := h.Service.appBaseURL + "/auth/social/callback?code=" + url.QueryEscape(res.Code)
	http.Redirect(w, r, target, http.StatusFound)
}

// platformCallbackAnswered completes a platform (organization-less) console
// sign-in, bouncing the SPA to /sign-in with a one-time code to exchange, and
// reports whether it answered: it falls through to the organization flow only
// when the state isn't a platform state.
func (h *Handler) platformCallbackAnswered(w http.ResponseWriter, r *http.Request, provider, state, code string, startedHere bool) bool {
	if !h.Service.PlatformProviderEnabled(provider) {
		return false
	}
	res, perr := h.Service.CompletePlatformCallback(r.Context(), provider, state, code, startedHere)
	if perr == nil {
		if res.LinkCode != "" {
			// Authenticated link ceremony: no session issued — return to the
			// account page, which completes the link as the account that
			// began it (POST /v1/social/link/complete).
			q := url.Values{"link_code": {res.LinkCode}, "provider": {res.Provider}}
			http.Redirect(w, r, h.Service.appBaseURL+"/account/security?"+q.Encode(), http.StatusFound)
		} else {
			h.binding().Remove(w, r, state)
			http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_code="+url.QueryEscape(res.LoginCode), http.StatusFound)
		}
		return true
	}
	// A suspended or deleted account: say so on the console's own sign-in
	// page, not the hosted login's.
	if errors.Is(perr, errs.ErrAuthAccountInactive) {
		http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=account_inactive", http.StatusFound)
		return true
	}
	// A sign-in begun in another browser: say so, so the person starts it
	// again here.
	if errors.Is(perr, ErrBrowserMismatch) {
		http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=other_browser", http.StatusFound)
		return true
	}
	// Sign-in with a provider that has no account yet: bounce to sign-in with
	// a clear "sign up first" signal instead of silently creating an account.
	if errors.Is(perr, ErrNoAccount) {
		http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=no_account", http.StatusFound)
		return true
	}
	// An account uses the address but hasn't proved owning it: say so, so
	// the person verifies it or resets its password first.
	if errors.Is(perr, ErrAccountUnverified) {
		http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=account_unverified", http.StatusFound)
		return true
	}
	if !errors.Is(perr, ErrStateInvalid) {
		h.redirectSocialError(w, r, perr)
		return true
	}
	return false
}

// finishHostedSignIn ends a social sign-in the hosted login began: an address the organization refuses
// is told so on the hosted login, as with every other method, not shown a provider failure; otherwise
// it sets the SSO cookie and returns to /oauth/authorize, or first hands the hosted login a
// second-factor challenge.
func (h *Handler) finishHostedSignIn(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
	// An address the organization refuses is told so on the hosted login,
	// as every other method is, not shown a provider failure.
	if aerr := h.Service.CheckHostedSignIn(r.Context(), res.OrganizationID, res.UserID, httpx.ClientIP(r)); aerr != nil {
		if errors.Is(aerr, errs.ErrAuthAddressNotAllowed) && h.LoginBaseURL != "" {
			q := url.Values{"error": {"address_not_allowed"}, "return_to": {res.ReturnTo}}
			http.Redirect(w, r, h.LoginBaseURL+"/sign-in?"+q.Encode(), http.StatusFound)
			return
		}
		h.redirectSocialError(w, r, aerr)
		return
	}
	// Hosted flow: set the SSO cookie and return to /oauth/authorize — or,
	// when the sign-in must meet a second factor first, hand the challenge to
	// the hosted login. It travels in the fragment, which the
	// browser never sends to a server or in a Referer.
	trusted := ""
	if c, cerr := r.Cookie(authentication.TrustedDeviceCookie); cerr == nil {
		trusted = c.Value
	}
	ls, serr := h.Service.BeginLoginSession(r.Context(), res.UserID, res.OrganizationID, httpx.ClientIP(r), r.UserAgent(),
		trusted, httpx.GeoCountry(r.Context()))
	if serr != nil {
		h.redirectSocialError(w, r, serr)
		return
	}
	if ls.MFARequired {
		if h.LoginBaseURL == "" {
			h.redirectSocialError(w, r, errs.ErrInternalServer)
			return
		}
		http.Redirect(w, r, h.LoginBaseURL+"/sign-in?"+url.Values{"return_to": {res.ReturnTo}}.Encode()+"#"+challengeFragment(ls.MFAChallenge), http.StatusFound)
		return
	}
	authentication.SetLoginSessionCookie(w, ls.RawCookie, h.CookieSecure)
	http.Redirect(w, r, res.ReturnTo, http.StatusFound) // #nosec G710 -- checked against the allowed origins before it was stored with the sign-in state
}
