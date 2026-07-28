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
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SetPlatformProvider registers a platform-level provider (config from env).
func (s *Service) SetPlatformProvider(name, clientID, clientSecret, discoveryURL string) {
	if s.platform == nil {
		s.platform = map[string]providerConfig{}
	}
	s.platform[name] = providerConfig{clientID: clientID, clientSecret: clientSecret, discoveryURL: discoveryURL}
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

// BeginPlatformLogin persists PKCE state and returns the provider authorization
// URL for a tenant-less console sign-in.
func (s *Service) BeginPlatformLogin(ctx context.Context, provider, redirectURI string) (string, error) {
	pc, ok := s.platform[provider]
	if !ok {
		return "", errs.ErrSocialProviderNotConfigured
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
		INSERT INTO auth.platform_social_states (state_hash, provider, code_verifier, redirect_uri, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		stateHash, provider, verifier, redirectURI, time.Now().UTC().Add(socialStateTTL),
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

// CompletePlatformCallback consumes the state, exchanges the code, resolves or
// creates the tenant-less user by global email, and mints a one-time login code
// the SPA trades for a session. Returns ErrSocialStateInvalid when the state
// isn't a platform state, so the caller can fall back to the tenant flow.
func (s *Service) CompletePlatformCallback(ctx context.Context, provider, state, code string) (string, error) {
	if state == "" || code == "" {
		return "", errs.ErrSocialCallbackParamsMissing
	}
	pc, ok := s.platform[provider]
	if !ok {
		return "", errs.ErrSocialProviderNotConfigured
	}
	stateHash := codes.Hash(state)

	// Single-use: delete the state row as we read it.
	var (
		gotProvider, verifier, redirectURI string
		expiresAt                          time.Time
	)
	err := s.pool.QueryRow(ctx, `
		DELETE FROM auth.platform_social_states WHERE state_hash = $1
		RETURNING provider, code_verifier, redirect_uri, expires_at`, stateHash,
	).Scan(&gotProvider, &verifier, &redirectURI, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrSocialStateInvalid
	}
	if err != nil {
		return "", err
	}
	if gotProvider != provider {
		return "", errs.ErrSocialProviderMismatch
	}
	if time.Now().After(expiresAt) {
		return "", errs.ErrSocialStateExpired
	}

	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return "", errs.ErrSocialDiscoveryFailed.Wrap(err)
	}
	accessToken, err := s.oauth.exchange(ctx, doc, pc.clientID, pc.clientSecret, code, redirectURI, verifier)
	if err != nil {
		return "", errs.ErrSocialTokenExchangeFailed.Wrap(err)
	}
	ui, err := s.oauth.userinfo(ctx, doc, accessToken)
	if err != nil {
		return "", errs.ErrSocialUserinfoFailed.Wrap(err)
	}
	if ui.Email == "" {
		return "", errs.ErrSocialEmailMissing
	}

	userID, err := s.findOrCreatePlatformUser(ctx, ui)
	if err != nil {
		return "", err
	}

	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.platform_social_codes (code_hash, user_id, expires_at)
		VALUES ($1, $2, $3)`,
		codeHash, userID, time.Now().UTC().Add(socialCodeTTL),
	); err != nil {
		return "", err
	}
	return rawCode, nil
}

// findOrCreatePlatformUser resolves a tenant-less Qeet ID user by globally-unique
// email, creating a password-less one if none exists (they create their first
// org from the dashboard, exactly like a normal tenant-less signup).
func (s *Service) findOrCreatePlatformUser(ctx context.Context, ui userInfo) (uuid.UUID, error) {
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
