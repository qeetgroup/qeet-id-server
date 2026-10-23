package social

// Platform sign-in is the console's own tenant-less social sign-in. It uses
// env-configured providers and its own state and code tables, matches people by
// their globally unique email, and issues a tenant-less session.

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

// SetPlatformApple registers Sign in with Apple. servicesID is the Services ID;
// the client secret is signed per request from teamID, keyID and privateKey (a
// .p8 key). See apple.go.
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
	nonce, nonceHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.platform_social_states
		    (state_hash, provider, code_verifier, redirect_uri, expires_at, link_user_id, allow_create, nonce_hash)
		VALUES ($1, $2, '', $3, $4, $5, $6, $7)`,
		stateHash, provider, redirectURI, time.Now().UTC().Add(socialStateTTL), linkArg(linkUserID), allowCreate, nonceHash,
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
		"nonce":         {nonce},
	}
	return appleAuthorizeURL + "?" + q.Encode(), nil
}

// PlatformCallbackResult is the outcome of a platform OAuth callback: a login
// ceremony yields a one-time LoginCode the SPA trades for a session; an
// authenticated link ceremony yields a one-time LinkCode the account that began
// it completes the link with (CompletePlatformLink). Neither issues a session.
type PlatformCallbackResult struct {
	LoginCode string
	LinkCode  string
	Provider  string
}

func emailPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CompletePlatformCallback consumes the state and exchanges the code. A sign-in
// yields a one-time LoginCode and needs startedHere (else ErrSocialBrowserMismatch);
// a link yields a LinkCode for CompletePlatformLink. ErrSocialStateInvalid means
// the state isn't a platform one, so the caller can try the tenant flow.
func (s *Service) CompletePlatformCallback(ctx context.Context, provider, state, code string, startedHere bool) (*PlatformCallbackResult, error) {
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
		nonceHash                          *string
		allowCreate                        bool
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM auth.platform_social_states WHERE state_hash = $1
		RETURNING provider, code_verifier, redirect_uri, expires_at, link_user_id, allow_create, nonce_hash`, stateHash,
	).Scan(&gotProvider, &verifier, &redirectURI, &expiresAt, &linkUserID, &allowCreate, &nonceHash)
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
	// A sign-in completes only in the browser that began it. A link is begun
	// through the console's server, which sets no cookie in the browser; it is
	// bound to its account instead, when the account completes it.
	if linkUserID == nil && !startedHere {
		return nil, errs.ErrSocialBrowserMismatch
	}

	var ui userInfo
	switch pc.kind {
	case "github":
		accessToken, err := s.oauth.githubExchange(ctx, pc.clientID, pc.clientSecret, code, redirectURI)
		if err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		if ui, err = s.oauth.githubUserinfo(ctx, accessToken); err != nil {
			return nil, errs.ErrSocialUserinfoFailed.Wrap(err)
		}
	case "apple":
		if nonceHash == nil || *nonceHash == "" {
			return nil, errs.ErrSocialStateInvalid
		}
		secret, err := appleClientSecret(pc.clientID, pc.teamID, pc.keyID, pc.privateKey)
		if err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		if ui, err = s.oauth.appleExchange(ctx, secret, pc.clientID, code, redirectURI, *nonceHash); err != nil {
			return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
	default:
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
	// A link ceremony doesn't attach here: whoever arrived may not be the
	// account that began it. What the provider returned waits under a one-time
	// code that only that account can complete.
	if linkUserID != nil {
		verifiedEmail := ""
		if ui.EmailVerified {
			verifiedEmail = ui.Email
		}
		rawCode, codeHash, err := codes.URLToken()
		if err != nil {
			return nil, err
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO auth.platform_social_link_codes (code_hash, user_id, provider, subject, email, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			codeHash, *linkUserID, provider, ui.Subject, emailPtr(verifiedEmail), time.Now().UTC().Add(socialCodeTTL),
		); err != nil {
			return nil, err
		}
		return &PlatformCallbackResult{LinkCode: rawCode, Provider: provider}, nil
	}

	owner, ownerErr := s.q.GetPlatformSocialIdentityOwner(ctx, dbgen.GetPlatformSocialIdentityOwnerParams{
		Provider: provider,
		Subject:  ui.Subject,
	})
	if ownerErr != nil && !errors.Is(ownerErr, pgx.ErrNoRows) {
		return nil, ownerErr
	}

	var userID uuid.UUID
	if ownerErr == nil {
		// Existing provider-subject binding is the identity proof; an upstream
		// provider omitting email on later logins does not break the account.
		userID = owner
	} else {
		if ui.Email == "" {
			return nil, errs.ErrSocialEmailMissing
		}
		if !ui.EmailVerified {
			return nil, errs.ErrSocialEmailUnverified
		}
		// New login/signup binding: verified email may resolve an existing local
		// account or provision a new one when this is a signup ceremony.
		userID, err = s.findOrCreatePlatformUser(ctx, ui, allowCreate)
		if err != nil {
			return nil, err
		}
		if err := s.q.UpsertPlatformSocialIdentity(ctx, dbgen.UpsertPlatformSocialIdentityParams{
			UserID: userID, Provider: provider, Subject: ui.Subject, Email: emailPtr(ui.Email),
		}); err != nil {
			return nil, err
		}
	}

	// A suspended or deleted account gets no code to sign in with.
	if err := s.auth.CheckSignInAccount(ctx, userID, uuid.Nil, "social", "", ""); err != nil {
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

// CompletePlatformLink attaches the identity held under rawCode to userID and
// returns the provider. Only the account that began the link may complete it,
// but the code is spent either way. Email isn't checked, since the signed-in
// account is the proof; an identity linked to someone else is refused.
func (s *Service) CompletePlatformLink(ctx context.Context, rawCode string, userID uuid.UUID) (string, error) {
	if rawCode == "" {
		return "", errs.ErrSocialCodeRequired
	}
	var (
		linkUserID        uuid.UUID
		provider, subject string
		email             *string
		expiresAt         time.Time
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM auth.platform_social_link_codes WHERE code_hash = $1
		RETURNING user_id, provider, subject, email, expires_at`, codes.Hash(rawCode),
	).Scan(&linkUserID, &provider, &subject, &email, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrSocialLinkCodeInvalid
	}
	if err != nil {
		return "", err
	}
	if time.Now().After(expiresAt) {
		return "", errs.ErrSocialLinkCodeInvalid
	}
	if linkUserID != userID {
		return "", errs.ErrSocialLinkAccountMismatch
	}
	owner, err := s.q.GetPlatformSocialIdentityOwner(ctx, dbgen.GetPlatformSocialIdentityOwnerParams{
		Provider: provider,
		Subject:  subject,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if err == nil && owner != userID {
		return "", errs.ErrSocialAlreadyLinked
	}
	if err := s.q.UpsertPlatformSocialIdentity(ctx, dbgen.UpsertPlatformSocialIdentityParams{
		UserID:   userID,
		Provider: provider,
		Subject:  subject,
		Email:    email,
	}); err != nil {
		return "", err
	}
	return provider, nil
}

// findOrCreatePlatformUser returns the user with ui.Email. With none, it creates
// a password-less tenant-less user when allowCreate (sign-up) and otherwise
// fails with ErrSocialNoAccount.
func (s *Service) findOrCreatePlatformUser(ctx context.Context, ui userInfo, allowCreate bool) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`, ui.Email,
	).Scan(&userID)
	if err == nil {
		// Adopt the account only if it has proved owning the address, or a squatter
		// who registered it unverified keeps a working password on it.
		if err := requireVerifiedAddress(ctx, s.pool, userID); err != nil {
			return uuid.Nil, err
		}
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
// token pair, or the second-factor challenge to meet first. A code that isn't a
// platform one fails with ErrSocialLoginCodeInvalid, so the caller can try the
// tenant exchange.
func (s *Service) ExchangePlatformLogin(ctx context.Context, rawCode, ip, ua string) (*auth.LoginResult, error) {
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
	// Tenant-less, exactly like signup.
	return s.auth.BeginSocialSignIn(ctx, userID, uuid.Nil, ip, ua)
}
