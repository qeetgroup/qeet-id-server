package social

// Platform-level (tenant-less) social login for the console's own Qeet ID
// accounts. The per-tenant social flow (social.go) requires a tenant; the
// console sign-in has none, so this parallel path uses env-configured providers,
// dedicated tenant-less state/code tables (migration 0085), resolves the user by
// globally-unique email, and issues a tenant-less session — reusing the same
// generic OIDC ceremony (oauthclient.go).

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SetPlatformProvider registers a discovery-based OIDC provider (Google,
// Microsoft, …) at platform level (config from env).
func (s *Service) SetPlatformProvider(name, clientID, clientSecret, discoveryURL string) {
	s.setPlatform(name, providerConfig{clientID: clientID, clientSecret: clientSecret, discoveryURL: discoveryURL, kind: "oidc"})
}

// SetPlatformGitHub registers GitHub, which isn't OIDC (no discovery doc), so it
// uses the dedicated adapter in github.go instead of the generic OIDC ceremony.
func (s *Service) SetPlatformGitHub(clientID, clientSecret string) {
	s.setPlatform("github", providerConfig{clientID: clientID, clientSecret: clientSecret, kind: "github"})
}

// SetPlatformApple registers Sign in with Apple. clientID is the Services ID; the
// client secret is derived per-request as a signed ES256 JWT from teamID/keyID/
// privateKey (a .p8 key). See apple.go.
func (s *Service) SetPlatformApple(servicesID, teamID, keyID, privateKey string) {
	s.setPlatform("apple", providerConfig{
		clientID: servicesID, kind: "apple", teamID: teamID, keyID: keyID, privateKey: privateKey,
	})
}

func (s *Service) setPlatform(name string, pc providerConfig) {
	if s.platform == nil {
		s.platform = map[string]providerConfig{}
	}
	s.platform[name] = pc
}

// PlatformProviderEnabled reports whether a platform provider is configured.
func (s *Service) PlatformProviderEnabled(name string) bool {
	_, ok := s.platform[name]
	return ok
}

// PlatformProviderNames lists the configured platform provider names (for the
// frontend to know which buttons to enable).
func (s *Service) PlatformProviderNames() []string {
	out := make([]string, 0, len(s.platform))
	for k := range s.platform {
		out = append(out, k)
	}
	return out
}

// linkArg maps a link user id to a nullable bind: uuid.Nil (an ordinary
// login/signup ceremony) becomes SQL NULL.
func linkArg(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// BeginPlatformLogin persists PKCE state and returns the provider authorization
// URL for a tenant-less console sign-in / sign-up. allowCreate=true (sign-up)
// lets the callback provision a new account just-in-time; false (sign-in) makes
// it require an existing account instead of silently creating one.
func (s *Service) BeginPlatformLogin(ctx context.Context, provider, redirectURI string, allowCreate bool) (string, error) {
	return s.beginPlatform(ctx, provider, redirectURI, uuid.Nil, allowCreate)
}

// BeginPlatformLink starts an authenticated "connect this provider to my
// account" ceremony. The callback attaches the resulting identity to userID
// instead of logging in / creating an account — the account-page link flow.
func (s *Service) BeginPlatformLink(ctx context.Context, provider, redirectURI string, userID uuid.UUID) (string, error) {
	return s.beginPlatform(ctx, provider, redirectURI, userID, false)
}

func (s *Service) beginPlatform(ctx context.Context, provider, redirectURI string, linkUserID uuid.UUID, allowCreate bool) (string, error) {
	pc, ok := s.platform[provider]
	if !ok {
		return "", errs.ErrSocialProviderNotConfigured
	}
	if pc.kind == "github" {
		return s.beginGitHubLogin(ctx, provider, pc, redirectURI, linkUserID, allowCreate)
	}
	if pc.kind == "apple" {
		return s.beginAppleLogin(ctx, provider, pc, redirectURI, linkUserID, allowCreate)
	}
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return "", errs.ErrSocialDiscoveryFailed.Wrap(err)
	}
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	state, stateHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.platform_social_states (state_hash, provider, code_verifier, redirect_uri, expires_at, link_user_id, allow_create)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		stateHash, provider, verifier, redirectURI, time.Now().UTC().Add(socialStateTTL), linkArg(linkUserID), allowCreate,
	); err != nil {
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

// beginGitHubLogin starts GitHub's OAuth authorize flow — no OIDC discovery and
// no PKCE (GitHub OAuth Apps don't support it), so state is stored with an empty
// verifier.
func (s *Service) beginGitHubLogin(ctx context.Context, provider string, pc providerConfig, redirectURI string, linkUserID uuid.UUID, allowCreate bool) (string, error) {
	state, stateHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.platform_social_states (state_hash, provider, code_verifier, redirect_uri, expires_at, link_user_id, allow_create)
		VALUES ($1, $2, '', $3, $4, $5, $6)`,
		stateHash, provider, redirectURI, time.Now().UTC().Add(socialStateTTL), linkArg(linkUserID), allowCreate,
	); err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":    {pc.clientID},
		"redirect_uri": {redirectURI},
		"scope":        {githubScopes},
		"state":        {state},
		"allow_signup": {"true"},
	}
	return githubAuthorizeURL + "?" + q.Encode(), nil
}

// beginAppleLogin starts Sign in with Apple. Requesting name/email forces
// response_mode=form_post, so Apple returns to the callback via POST.
func (s *Service) beginAppleLogin(ctx context.Context, provider string, pc providerConfig, redirectURI string, linkUserID uuid.UUID, allowCreate bool) (string, error) {
	state, stateHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.platform_social_states (state_hash, provider, code_verifier, redirect_uri, expires_at, link_user_id, allow_create)
		VALUES ($1, $2, '', $3, $4, $5, $6)`,
		stateHash, provider, redirectURI, time.Now().UTC().Add(socialStateTTL), linkArg(linkUserID), allowCreate,
	); err != nil {
		return "", err
	}
	q := url.Values{
		"response_type": {"code"},
		"response_mode": {"form_post"},
		"client_id":     {pc.clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {appleScopes},
		"state":         {state},
	}
	return appleAuthorizeURL + "?" + q.Encode(), nil
}

// PlatformCallbackResult is the outcome of a platform OAuth callback: a login
// ceremony yields a one-time LoginCode the SPA trades for a session; an
// authenticated link ceremony sets Linked (no session is issued).
type PlatformCallbackResult struct {
	LoginCode string
	Linked    bool
	Provider  string
}

func emailPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CompletePlatformCallback consumes the state and exchanges the code. For a
// login ceremony it resolves/creates the tenant-less user by global email,
// records the connected identity, and mints a one-time login code. For a link
// ceremony (state carried a link_user_id) it attaches the identity to *that*
// user without creating or switching accounts — refusing an identity already
// linked to someone else. Returns ErrSocialStateInvalid when the state isn't a
// platform state, so the caller can fall back to the tenant flow.
func (s *Service) CompletePlatformCallback(ctx context.Context, provider, state, code string) (*PlatformCallbackResult, error) {
	if state == "" || code == "" {
		return nil, errs.ErrSocialCallbackParamsMissing
	}
	pc, ok := s.platform[provider]
	if !ok {
		return nil, errs.ErrSocialProviderNotConfigured
	}
	stateHash := codes.Hash(state)

	// Single-use: delete the state row as we read it.
	var (
		gotProvider, verifier, redirectURI string
		expiresAt                          time.Time
		linkUserID                         *uuid.UUID
		allowCreate                        bool
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM auth.platform_social_states WHERE state_hash = $1
		RETURNING provider, code_verifier, redirect_uri, expires_at, link_user_id, allow_create`, stateHash,
	).Scan(&gotProvider, &verifier, &redirectURI, &expiresAt, &linkUserID, &allowCreate)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrSocialStateInvalid
	}
	if err != nil {
		return nil, err
	}
	if gotProvider != provider {
		return nil, errs.ErrSocialProviderMismatch
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrSocialStateExpired
	}

	var ui userInfo
	if pc.kind == "github" {
		accessToken, err := s.oauth.githubExchange(ctx, pc.clientID, pc.clientSecret, code, redirectURI)
		if err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		if ui, err = s.oauth.githubUserinfo(ctx, accessToken); err != nil {
			return nil, errs.ErrSocialUserinfoFailed.Wrap(err)
		}
	} else if pc.kind == "apple" {
		secret, err := appleClientSecret(pc.clientID, pc.teamID, pc.keyID, pc.privateKey)
		if err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		if ui, err = s.oauth.appleExchange(ctx, secret, pc.clientID, code, redirectURI); err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
	} else {
		doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
		if err != nil {
			return nil, errs.ErrSocialDiscoveryFailed.Wrap(err)
		}
		accessToken, err := s.oauth.exchange(ctx, doc, pc.clientID, pc.clientSecret, code, redirectURI, verifier)
		if err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		if ui, err = s.oauth.userinfo(ctx, doc, accessToken); err != nil {
			return nil, errs.ErrSocialUserinfoFailed.Wrap(err)
		}
	}
	if ui.Email == "" {
		return nil, errs.ErrSocialEmailMissing
	}

	// Link ceremony: attach the identity to the initiating user. Never create or
	// switch accounts; refuse an identity already linked to a different user.
	if linkUserID != nil {
		owner, oerr := s.q.GetPlatformSocialIdentityOwner(ctx, dbgen.GetPlatformSocialIdentityOwnerParams{
			Provider: provider,
			Subject:  ui.Subject,
		})
		if oerr != nil && !errors.Is(oerr, pgx.ErrNoRows) {
			return nil, oerr
		}
		if oerr == nil && owner != *linkUserID {
			return nil, errs.ErrSocialAlreadyLinked
		}
		if err := s.q.UpsertPlatformSocialIdentity(ctx, dbgen.UpsertPlatformSocialIdentityParams{
			UserID:   *linkUserID,
			Provider: provider,
			Subject:  ui.Subject,
			Email:    emailPtr(ui.Email),
		}); err != nil {
			return nil, err
		}
		return &PlatformCallbackResult{Linked: true, Provider: provider}, nil
	}

	// Login / signup ceremony. allowCreate distinguishes them: sign-up may
	// provision just-in-time; sign-in requires an existing account.
	userID, err := s.findOrCreatePlatformUser(ctx, ui, allowCreate)
	if err != nil {
		return nil, err
	}
	// Record the identity so the account shows this provider as connected — and
	// so a provider the user already signs in with can't be "linked" again.
	if err := s.q.UpsertPlatformSocialIdentity(ctx, dbgen.UpsertPlatformSocialIdentityParams{
		UserID:   userID,
		Provider: provider,
		Subject:  ui.Subject,
		Email:    emailPtr(ui.Email),
	}); err != nil {
		return nil, err
	}

	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.platform_social_codes (code_hash, user_id, expires_at)
		VALUES ($1, $2, $3)`,
		codeHash, userID, time.Now().UTC().Add(socialCodeTTL),
	); err != nil {
		return nil, err
	}
	return &PlatformCallbackResult{LoginCode: rawCode, Provider: provider}, nil
}

// findOrCreatePlatformUser resolves a tenant-less Qeet ID user by globally-unique
// email, creating a password-less one if none exists (they create their first
// org from the dashboard, exactly like a normal tenant-less signup).
func (s *Service) findOrCreatePlatformUser(ctx context.Context, ui userInfo, allowCreate bool) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`, ui.Email,
	).Scan(&userID)
	if err == nil {
		// Existing account: adopt the provider's avatar only if none is set yet,
		// so we never clobber a picture the user chose themselves.
		if ui.Picture != "" {
			_, _ = s.pool.Exec(ctx,
				`UPDATE "user".users SET avatar_url = $2
				 WHERE id = $1 AND (avatar_url IS NULL OR avatar_url = '')`,
				userID, ui.Picture)
		}
		return userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	// No account for this email. Only a sign-up ceremony may provision one — a
	// sign-in must not silently create an account.
	if !allowCreate {
		return uuid.Nil, errs.ErrSocialNoAccount
	}
	var displayName, avatar *string
	if ui.Name != "" {
		displayName = &ui.Name
	}
	if ui.Picture != "" {
		avatar = &ui.Picture
	}
	if err := s.pool.QueryRow(ctx,
		`INSERT INTO "user".users (email, display_name, avatar_url) VALUES ($1, $2, $3) RETURNING id`,
		ui.Email, displayName, avatar,
	).Scan(&userID); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// ExchangePlatformLogin trades a one-time platform login code for a tenant-less
// Qeet token pair. Returns ErrSocialLoginCodeInvalid when the code isn't a
// platform code (so the caller can fall back to the tenant exchange).
func (s *Service) ExchangePlatformLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
	if rawCode == "" {
		return nil, errs.ErrSocialCodeRequired
	}
	codeHash := codes.Hash(rawCode)
	// Atomically claim an unused, unexpired code.
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		UPDATE auth.platform_social_codes
		SET used_at = NOW()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING user_id`, codeHash,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrSocialLoginCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	// Tenant-less session, exactly like signup.
	return s.auth.IssuePair(ctx, userID, uuid.Nil, ip, ua, "social")
}
