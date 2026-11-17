// Package social manages each organisation's external identity providers
// (Google, Microsoft, Okta, …) and the identities linked through them, and runs
// the OAuth 2.0 / OIDC sign-in with them, both per organisation and for the
// console's own tenant-less sign-in (platform.go).
package social

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Provider is a tenant's social identity provider, without its secret. Kind is
// oidc, found by DiscoveryURL, or the adapter its name picks (github,
// facebook, x, discord or apple); Apple's names its team and key.
type Provider struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	Kind         string    `json:"kind"`
	ClientID     string    `json:"client_id"`
	DiscoveryURL *string   `json:"discovery_url"`
	AppleTeamID  *string   `json:"apple_team_id,omitempty"`
	AppleKeyID   *string   `json:"apple_key_id,omitempty"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// ExternalIdentity is a social account linked to a user.
type ExternalIdentity struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Provider string    `json:"provider"`
	Subject  string    `json:"subject"`
	Email    *string   `json:"email"`
	LinkedAt time.Time `json:"linked_at"`
}

// Service manages social providers and runs social sign-in. platform holds the
// console's env-configured tenant-less providers (platform.go); returnOrigins is
// the return_to allowlist, keyed by normalized "scheme://host[:port]".
type Service struct {
	pool          *pgxpool.Pool
	q             *dbgen.Queries
	auth          *auth.Service
	appBaseURL    string
	oauth         *oauthClient
	egress        *egress.Policy
	box           *envelope.Cipher
	capture       auth.DomainCapture
	platform      map[string]providerConfig
	returnOrigins map[string]struct{}
}

// SetDomainCapture sets the check that keeps a provider from creating an
// account on a domain whose organisation requires single sign-on (nil: no
// address is captured).
func (s *Service) SetDomainCapture(c auth.DomainCapture) { s.capture = c }

// SetAllowedReturnOrigins sets the origins a return_to may point at. With none,
// only root-relative paths are accepted.
func (s *Service) SetAllowedReturnOrigins(origins ...string) {
	set := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		if norm := normalizeOrigin(o); norm != "" {
			set[norm] = struct{}{}
		}
	}
	s.returnOrigins = set
}

// normalizeOrigin reduces a URL or origin string to "scheme://host[:port]",
// or "" if it is not an absolute URL with a host.
func normalizeOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// validateReturnTo accepts "" (no hosted flow), a path with a single leading
// "/", or an absolute URL without userinfo on an allowed origin. The callback
// redirects there after setting the SSO cookie. Whitespace, control characters
// and backslashes are refused anywhere, as browsers rewrite or drop them.
func (s *Service) validateReturnTo(returnTo string) error {
	if returnTo == "" {
		return nil
	}
	if !utf8.ValidString(returnTo) || strings.ContainsFunc(returnTo, func(r rune) bool {
		return r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return errs.ErrSocialReturnToInvalid
	}
	u, err := url.Parse(returnTo)
	if err != nil || u.User != nil {
		return errs.ErrSocialReturnToInvalid
	}
	if returnTo[0] == '/' {
		if strings.HasPrefix(returnTo, "//") || u.Scheme != "" || u.Host != "" {
			return errs.ErrSocialReturnToInvalid
		}
		return nil
	}
	if u.Scheme == "" || u.Host == "" {
		return errs.ErrSocialReturnToInvalid
	}
	if _, ok := s.returnOrigins[strings.ToLower(u.Scheme+"://"+u.Host)]; !ok {
		return errs.ErrSocialReturnToInvalid
	}
	return nil
}

// SetCipher sets the cipher that encrypts social sign-in secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// NewService returns the social sign-in service.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	return &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
		oauth:      newOAuthClient(policy),
		egress:     policy,
	}
}

// CreateProviderInput adds a provider, or replaces the settings of one the
// organisation already has. Replacing keeps whether it is switched on, and an
// empty ClientSecret keeps the stored secret (a new provider needs one).
// DiscoveryURL is an OpenID Connect provider's alone. For Apple, ClientID is
// the Services ID and ClientSecret the .p8 private key, with AppleTeamID and
// AppleKeyID; the client secret is signed from them for each sign-in.
// ChangedBy is who saved it, for the audit record.
type CreateProviderInput struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	DiscoveryURL string    `json:"discovery_url"`
	AppleTeamID  string    `json:"apple_team_id"`
	AppleKeyID   string    `json:"apple_key_id"`
	ChangedBy    ChangedBy `json:"-"`
}

// checkAppleKey refuses an Apple private key, team ID and key ID that can't
// sign a client secret.
func checkAppleKey(servicesID, teamID, keyID, privateKey string) error {
	if _, err := appleClientSecret(servicesID, teamID, keyID, privateKey); err != nil {
		return errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "client_secret", Code: "invalid", Message: "Enter the .p8 private key Apple gave for the key ID.",
		}})
	}
	return nil
}

// UpsertProvider adds or updates one of the tenant's social providers.
func (s *Service) UpsertProvider(ctx context.Context, in CreateProviderInput) (*Provider, error) {
	kind := adapterKind(in.Provider)
	if kind == kindOIDC {
		if _, err := s.egress.ValidateHTTPURL(in.DiscoveryURL); err != nil {
			return nil, errs.ErrSocialProviderNoDiscovery
		}
	} else {
		in.DiscoveryURL = ""
	}
	if kind != kindApple {
		in.AppleTeamID, in.AppleKeyID = "", ""
	}
	if strings.TrimSpace(in.Provider) == "" || strings.TrimSpace(in.ClientID) == "" {
		return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{
			{Field: "client_id", Code: "required", Message: "Enter the provider and its client ID."},
		})
	}
	if kind == kindApple {
		if strings.TrimSpace(in.AppleTeamID) == "" || strings.TrimSpace(in.AppleKeyID) == "" {
			return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{
				{Field: "apple_team_id", Code: "required", Message: "Enter Apple's team ID and key ID."},
			})
		}
		if in.ClientSecret != "" {
			if err := checkAppleKey(in.ClientID, in.AppleTeamID, in.AppleKeyID, in.ClientSecret); err != nil {
				return nil, err
			}
		}
	}
	replaceSecret := in.ClientSecret != ""
	var ciphertext, nonce []byte
	if replaceSecret {
		var err error
		if ciphertext, nonce, err = s.sealSecret(in.TenantID, in.Provider, in.ClientSecret); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var existingID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM tenant.social_providers WHERE tenant_id = $1 AND provider = $2 FOR UPDATE`,
		in.TenantID, in.Provider).Scan(&existingID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	existing := err == nil
	if !existing && !replaceSecret {
		return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{
			{Field: "client_secret", Code: "required", Message: "Enter the client secret."},
		})
	}
	var r struct {
		ID                      uuid.UUID
		TenantID                uuid.UUID
		Provider, ClientID      string
		DiscoveryURL            *string
		AppleTeamID, AppleKeyID *string
		Enabled                 bool
		CreatedAt               time.Time
	}
	if existing {
		// Replacing keeps whether the provider is switched on, and the stored
		// secret when none is given.
		err = tx.QueryRow(ctx, `
			UPDATE tenant.social_providers SET
			    client_id = $3,
			    discovery_url = NULLIF($6, ''),
			    client_secret = CASE WHEN $7::boolean THEN '' ELSE client_secret END,
			    client_secret_ct = CASE WHEN $7::boolean THEN $4 ELSE client_secret_ct END,
			    client_secret_nonce = CASE WHEN $7::boolean THEN $5 ELSE client_secret_nonce END,
			    encryption_version = CASE WHEN $7::boolean THEN 1 ELSE encryption_version END,
			    apple_team_id = NULLIF($8, ''),
			    apple_key_id = NULLIF($9, '')
			WHERE tenant_id = $1 AND provider = $2
			RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id
		`, in.TenantID, in.Provider, in.ClientID, ciphertext, nonce, in.DiscoveryURL, replaceSecret, in.AppleTeamID, in.AppleKeyID).Scan(
			&r.ID, &r.TenantID, &r.Provider, &r.ClientID, &r.DiscoveryURL, &r.Enabled, &r.CreatedAt, &r.AppleTeamID, &r.AppleKeyID,
		)
	} else {
		err = tx.QueryRow(ctx, `
			INSERT INTO tenant.social_providers
			    (tenant_id, provider, client_id, client_secret, client_secret_ct,
			     client_secret_nonce, encryption_version, discovery_url, apple_team_id, apple_key_id)
			VALUES ($1, $2, $3, '', $4, $5, 1, NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''))
			RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at, apple_team_id, apple_key_id
		`, in.TenantID, in.Provider, in.ClientID, ciphertext, nonce, in.DiscoveryURL, in.AppleTeamID, in.AppleKeyID).Scan(
			&r.ID, &r.TenantID, &r.Provider, &r.ClientID, &r.DiscoveryURL, &r.Enabled, &r.CreatedAt, &r.AppleTeamID, &r.AppleKeyID,
		)
		if pgxerr.IsUnique(err) {
			// Added by a concurrent save; this one is a replacement after all.
			return nil, errs.ErrConflict
		}
	}
	if err != nil {
		return nil, err
	}
	action, meta := "social_provider.created", map[string]any{"provider": in.Provider}
	if existing {
		action = "social_provider.updated"
		meta["fields"] = []string{"client_id", "discovery_url"}
		meta["secret_replaced"] = replaceSecret
	}
	if err := s.recordProviderChange(ctx, tx, in.ChangedBy, in.TenantID, r.ID, action, meta); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	p := Provider{
		ID:           r.ID,
		TenantID:     r.TenantID,
		Provider:     r.Provider,
		Kind:         kind,
		ClientID:     r.ClientID,
		DiscoveryURL: r.DiscoveryURL,
		AppleTeamID:  r.AppleTeamID,
		AppleKeyID:   r.AppleKeyID,
		Enabled:      r.Enabled,
		CreatedAt:    r.CreatedAt,
	}
	return &p, nil
}

// ListProviders returns the tenant's social providers.
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
			Kind:         adapterKind(r.Provider),
			ClientID:     r.ClientID,
			DiscoveryURL: r.DiscoveryUrl,
			AppleTeamID:  r.AppleTeamID,
			AppleKeyID:   r.AppleKeyID,
			Enabled:      r.Enabled,
			CreatedAt:    r.CreatedAt,
		}
	}
	return out, nil
}

// ListIdentities returns the social accounts linked to the user in the tenant.
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

// Unlink is an administrator removing an identity linked to an account in
// their organisation: tenant-scoped, so an identity can only be removed within
// its tenant. Refused when mayChange refuses the account (it runs before the
// transaction opens), and, recorded, when it is the account's only way to sign
// in.
func (s *Service) Unlink(ctx context.Context, id, tenantID uuid.UUID, by user.Remover, mayChange func(owner uuid.UUID) error) error {
	// The account's other ways to sign in span its organisations.
	ctx = postgres.AcrossTenants(ctx)
	var owner uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT user_id FROM "user".external_identities WHERE id = $1 AND tenant_id = $2`,
		id, tenantID).Scan(&owner); errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	} else if err != nil {
		return err
	}
	if err := mayChange(owner); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, owner)
	if err != nil {
		return err
	}
	n, err := s.q.WithTx(tx).DeleteExternalIdentity(ctx, dbgen.DeleteExternalIdentityParams{
		ID:       id,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		tid := tenantID
		return user.RefuseLastMethodRemoval(ctx, s.pool, owner, &tid, "linked_identity", id, by)
	}
	return tx.Commit(ctx)
}

// ListIdentitiesForUser returns the caller's connected social accounts. Console
// accounts are tenant-less, so this reads the platform identities table (which
// platform sign-in and the link flow populate) rather than the tenant-scoped
// "user".external_identities.
func (s *Service) ListIdentitiesForUser(ctx context.Context, userID uuid.UUID) ([]ExternalIdentity, error) {
	rows, err := s.q.ListPlatformSocialIdentitiesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]ExternalIdentity, len(rows))
	for i, r := range rows {
		out[i] = ExternalIdentity{
			ID:       r.ID,
			UserID:   r.UserID,
			Provider: r.Provider,
			Subject:  r.Subject,
			Email:    r.Email,
			LinkedAt: r.LinkedAt,
		}
	}
	return out, nil
}

// UnlinkForUser removes one of the caller's connected platform social
// accounts. ErrNotFound when it is not theirs (nothing is removed); refused,
// and recorded, when it is their account's only way to sign in.
func (s *Service) UnlinkForUser(ctx context.Context, id, userID uuid.UUID, by user.Remover) error {
	// The account's other ways to sign in span its organisations.
	ctx = postgres.AcrossTenants(ctx)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	methods, err := user.LockSignInMethods(ctx, tx, userID)
	if err != nil {
		return err
	}
	n, err := s.q.WithTx(tx).DeletePlatformSocialIdentityForUser(ctx, dbgen.DeletePlatformSocialIdentityForUserParams{
		ID:     id,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		return user.RefuseLastMethodRemoval(ctx, s.pool, userID, nil, "linked_identity", id, by)
	}
	return tx.Commit(ctx)
}

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

// resolveTenant maps a tenant id (uuid) or slug to a tenant id.
func (s *Service) resolveTenant(ctx context.Context, ref string) (uuid.UUID, error) {
	if ref == "" {
		return uuid.Nil, errs.ErrSocialTenantRequired
	}
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	id, err := s.q.GetTenantIDBySlug(ctx, ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrSocialTenantNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// loadProvider returns a tenant's enabled provider config: discovery-based for
// OpenID Connect, or for the adapter the provider's name picks.
func (s *Service) loadProvider(ctx context.Context, tenantID uuid.UUID, provider string) (providerConfig, error) {
	var pc providerConfig
	var enabled bool
	var clientID, legacySecret string
	var discoveryURL, teamID, keyID *string
	var ciphertext, nonce []byte
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret, client_secret_ct, client_secret_nonce,
		       discovery_url, enabled, apple_team_id, apple_key_id
		FROM tenant.social_providers
		WHERE tenant_id = $1 AND provider = $2
	`, tenantID, provider).Scan(&clientID, &legacySecret, &ciphertext, &nonce, &discoveryURL, &enabled, &teamID, &keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return pc, errs.ErrSocialProviderNotConfigured
	}
	if err != nil {
		return pc, err
	}
	// Switched off reads exactly like never set up: an unauthenticated
	// caller cannot tell an organisation has switched a provider off.
	if !enabled {
		return pc, errs.ErrSocialProviderNotConfigured
	}
	pc.kind = adapterKind(provider)
	if pc.kind == kindOIDC {
		if discoveryURL == nil || *discoveryURL == "" {
			return pc, errs.ErrSocialProviderNoDiscovery
		}
		pc.discoveryURL = *discoveryURL
	}
	if pc.kind == kindApple {
		if teamID == nil || keyID == nil {
			return pc, errs.ErrSocialProviderNotConfigured
		}
		pc.teamID, pc.keyID = *teamID, *keyID
	}
	pc.clientID = clientID
	if len(ciphertext) > 0 {
		if s.box == nil {
			return pc, errs.ErrSocialProviderNotConfigured
		}
		plain, openErr := s.box.Open(tenantID, "social-provider", provider, ciphertext, nonce)
		if openErr != nil {
			return pc, openErr
		}
		pc.clientSecret = string(plain)
		if pc.kind == kindApple {
			pc.privateKey = pc.clientSecret
		}
	} else {
		pc.clientSecret = legacySecret
		if legacySecret != "" && s.box != nil {
			ct, newNonce, sealErr := s.box.Seal(tenantID, "social-provider", provider, []byte(legacySecret))
			if sealErr != nil {
				return pc, sealErr
			}
			if _, updateErr := s.pool.Exec(ctx, `
				UPDATE tenant.social_providers
				SET client_secret = '', client_secret_ct = $3, client_secret_nonce = $4,
				    encryption_version = 1
				WHERE tenant_id = $1 AND provider = $2 AND client_secret_ct IS NULL
			`, tenantID, provider, ct, newNonce); updateErr != nil {
				return pc, updateErr
			}
		}
	}
	return pc, nil
}

// BeginLogin resolves the tenant + provider, persists CSRF state with a PKCE
// verifier, and returns the upstream authorization URL to redirect the user to.
func (s *Service) BeginLogin(ctx context.Context, provider, tenantRef, redirectURI, returnTo string) (string, error) {
	// Validate before anything is persisted, so a rejected value never reaches
	// the callback that would redirect to it.
	if err := s.validateReturnTo(returnTo); err != nil {
		return "", err
	}
	tenantID, err := s.resolveTenant(ctx, tenantRef)
	if err != nil {
		return "", err
	}
	pc, err := s.loadProvider(ctx, tenantID, provider)
	if err != nil {
		return "", err
	}
	var doc discoveryDoc
	if pc.kind == kindOIDC {
		if doc, err = s.oauth.discovery(ctx, pc.discoveryURL); err != nil {
			return "", errs.ErrSocialDiscoveryFailed.Wrap(err)
		}
		if err := checkAuthorizationEndpoint(doc.AuthorizationEndpoint); err != nil {
			return "", errs.ErrSocialProviderNoDiscovery.Wrap(err)
		}
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
	var nonce string
	var nonceHash *string
	if pc.kind == kindApple {
		raw, hash, err := codes.URLToken()
		if err != nil {
			return "", err
		}
		nonce, nonceHash = raw, &hash
	}
	if err := s.q.InsertSocialOAuthState(ctx, dbgen.InsertSocialOAuthStateParams{
		StateHash:    stateHash,
		TenantID:     tenantID,
		Provider:     provider,
		CodeVerifier: verifier,
		RedirectUri:  redirectURI,
		ReturnTo:     returnTo,
		ExpiresAt:    time.Now().UTC().Add(socialStateTTL),
		NonceHash:    nonceHash,
	}); err != nil {
		return "", err
	}
	switch pc.kind {
	case kindGitHub:
		return githubAuthorizeURL + "?" + url.Values{
			"client_id": {pc.clientID}, "redirect_uri": {redirectURI}, "scope": {githubScopes}, "state": {state},
		}.Encode(), nil
	case kindApple:
		// Asking for the name and address makes Apple answer by form_post.
		return appleAuthorizeURL + "?" + url.Values{
			"response_type": {"code"}, "response_mode": {"form_post"}, "client_id": {pc.clientID},
			"redirect_uri": {redirectURI}, "scope": {appleScopes}, "state": {state}, "nonce": {nonce},
		}.Encode(), nil
	case kindFacebook, kindX, kindDiscord:
		return s.oauth.oauth2AuthorizeURL(pc.kind, pc.clientID, redirectURI, state, challenge), nil
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

// CallbackResult is a successful callback's outcome: a one-time code the SPA
// trades for a session and, for the hosted flow, the return_to and the user and
// tenant to set the SSO cookie for.
type CallbackResult struct {
	Code     string
	ReturnTo string
	UserID   uuid.UUID
	TenantID uuid.UUID
}

// CompleteCallback consumes the state, exchanges the code, finds or creates the
// user and linked identity, and returns a one-time code the SPA trades for a
// session. Without startedHere it fails with ErrSocialBrowserMismatch; that error
// and a closed organisation still return the result's ReturnTo.
func (s *Service) CompleteCallback(ctx context.Context, provider, state, code string, startedHere bool) (*CallbackResult, error) {
	if state == "" || code == "" {
		return nil, errs.ErrSocialCallbackParamsMissing
	}
	stateHash := codes.Hash(state)

	// Single-use: delete the state row as we read it.
	st, err := s.q.ConsumeSocialOAuthState(ctx, stateHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrSocialStateInvalid
	}
	if err != nil {
		return nil, err
	}
	if st.Provider != provider {
		return nil, errs.ErrSocialProviderMismatch
	}
	if time.Now().After(st.ExpiresAt) {
		return nil, errs.ErrSocialStateExpired
	}
	if !startedHere {
		return &CallbackResult{ReturnTo: st.ReturnTo, TenantID: st.TenantID}, errs.ErrSocialBrowserMismatch
	}

	pc, err := s.loadProvider(ctx, st.TenantID, provider)
	if err != nil {
		return nil, err
	}
	ui, err := s.signedIn(ctx, pc, code, st.RedirectUri, st.CodeVerifier, st.NonceHash)
	if err != nil {
		return nil, err
	}
	userID, err := s.findOrCreateUser(ctx, st.TenantID, provider, ui)
	if errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) {
		// The return_to comes back with the refusal so the person lands on the
		// application's sign-in page, told why, rather than losing their way.
		if aerr := s.recordSignUpRefused(ctx, st.TenantID, provider, ui); aerr != nil {
			return nil, aerr
		}
		return &CallbackResult{ReturnTo: st.ReturnTo, TenantID: st.TenantID}, err
	}
	if err != nil {
		return nil, err
	}
	// An account already linked signs in no more once its organisation requires
	// single sign-on on its domain (adoption and sign-up were refused above).
	if err := s.refuseCapturedAccount(ctx, userID); err != nil {
		return nil, err
	}

	// A suspended or deleted account gets no code to sign in with.
	if err := s.auth.CheckSignInAccount(ctx, userID, st.TenantID, "social", "", ""); err != nil {
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
		Provider:  provider,
		ExpiresAt: time.Now().UTC().Add(socialCodeTTL),
	}); err != nil {
		return nil, err
	}
	return &CallbackResult{Code: rawCode, ReturnTo: st.ReturnTo, UserID: userID, TenantID: st.TenantID}, nil
}

// signedIn trades code with pc's provider and returns who signed in: through
// discovery for OpenID Connect, or the provider's adapter.
func (s *Service) signedIn(ctx context.Context, pc providerConfig, code, redirectURI, verifier string, nonceHash *string) (userInfo, error) {
	switch pc.kind {
	case kindGitHub:
		accessToken, err := s.oauth.githubExchange(ctx, pc.clientID, pc.clientSecret, code, redirectURI)
		if err != nil {
			return userInfo{}, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		ui, err := s.oauth.githubUserinfo(ctx, accessToken)
		if err != nil {
			return userInfo{}, errs.ErrSocialUserinfoFailed.Wrap(err)
		}
		return ui, nil
	case kindApple:
		if nonceHash == nil || *nonceHash == "" {
			return userInfo{}, errs.ErrSocialStateInvalid
		}
		secret, err := appleClientSecret(pc.clientID, pc.teamID, pc.keyID, pc.privateKey)
		if err != nil {
			return userInfo{}, errs.ErrSocialTokenExchangeFailed.Wrap(errors.Join(errAppleKey, err))
		}
		ui, err := s.oauth.appleExchange(ctx, secret, pc.clientID, code, redirectURI, *nonceHash)
		if err != nil {
			return userInfo{}, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		return ui, nil
	case kindFacebook, kindX, kindDiscord:
		accessToken, err := s.oauth.oauth2Exchange(ctx, pc.kind, pc.clientID, pc.clientSecret, code, redirectURI, verifier)
		if err != nil {
			return userInfo{}, errs.ErrSocialTokenExchangeFailed.Wrap(err)
		}
		ui, err := s.oauth.oauth2Userinfo(ctx, pc.kind, accessToken)
		if err != nil {
			return userInfo{}, errs.ErrSocialUserinfoFailed.Wrap(err)
		}
		return ui, nil
	}
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return userInfo{}, errs.ErrSocialDiscoveryFailed.Wrap(err)
	}
	accessToken, err := s.oauth.exchange(ctx, doc, pc.clientID, pc.clientSecret, code, redirectURI, verifier)
	if err != nil {
		return userInfo{}, errs.ErrSocialTokenExchangeFailed.Wrap(err)
	}
	ui, err := s.oauth.userinfo(ctx, doc, accessToken)
	if err != nil {
		return userInfo{}, errs.ErrSocialUserinfoFailed.Wrap(err)
	}
	return ui, nil
}

// EnabledProviderNames returns the names of a tenant's enabled social providers
// (for the hosted login app to render buttons). Satisfies oidc.ProviderLister.
func (s *Service) EnabledProviderNames(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	return s.q.EnabledSocialProviderNames(ctx, tenantID)
}

// BeginLoginSession signs a social-authenticated user in to the hosted login
// for tenantID, so social login can drive the OAuth authorize/consent flow: the
// SSO session cookie value, or the second-factor challenge to complete first
// (see auth.Service.BeginSocialLoginSession).
func (s *Service) BeginLoginSession(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, trustedToken, country string) (*auth.LoginSessionResult, error) {
	return s.auth.BeginSocialLoginSession(ctx, userID, tenantID, ip, ua, trustedToken, country)
}

// CheckHostedSignIn asks the organisation's address rules whether the browser
// at ip may finish a hosted social sign-in to it.
func (s *Service) CheckHostedSignIn(ctx context.Context, tenantID, userID uuid.UUID, ip string) error {
	return s.auth.CheckSignInAddress(ctx, tenantID, userID, ip, "hosted_social")
}

// findOrCreateUser links the external identity to an existing user (matched by
// provider subject, then by globally-unique email) or provisions a new
// password-less one. All in one tx so concurrent logins can't duplicate rows.
func (s *Service) findOrCreateUser(ctx context.Context, tenantID uuid.UUID, provider string, ui userInfo) (uuid.UUID, error) {
	// Whether the organisation allows self-registration is read before the
	// transaction, as the policy is read on another connection. It decides only
	// the branch below that creates an account.
	registration := s.requireSelfRegistration(ctx, tenantID)
	// The provider's word for the address is weighed before it too.
	vouch, err := s.vouchingFor(ctx, tenantID, provider, ui)
	if err != nil {
		return uuid.Nil, err
	}
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
		// A linked identity signs in only while this organisation is still the
		// account's home.
		home, herr := identitylink.HomeIn(ctx, tx, userID, tenantID)
		if herr != nil {
			return uuid.Nil, herr
		}
		if !home {
			return uuid.Nil, errs.ErrSocialAccountNotInTenant
		}
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	if ui.Email == "" {
		return uuid.Nil, errs.ErrSocialEmailMissing
	}

	// No linked identity yet: reuse a user with the same (globally-unique)
	// email, else create one. Only the reuse branch needs a verified address —
	// see the comments below.
	userID, err = q.GetUserByEmail(ctx, ui.Email)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Nobody the organisation knows: creating an account is
		// self-registration, so it follows the organisation's setting exactly
		// as password and passkey sign-up do. Refused before any write; the
		// caller records the attempt.
		if registration != nil {
			return uuid.Nil, registration
		}
		// Nor does a provider create an account on a domain that requires single
		// sign-on, or on one another organisation manages.
		if vouch.refusal != nil {
			return uuid.Nil, vouch.refusal
		}
		// An address the provider doesn't prove may name a new account (refusing
		// would lock out providers that omit the claim) but is never marked verified.
		// Raw SQL because InsertUserWithEmail always sets email_verified_at = NOW().
		var displayName *string
		if ui.Name != "" {
			displayName = &ui.Name
		}
		var verifiedAt *time.Time
		if vouch.proved {
			now := time.Now().UTC()
			verifiedAt = &now
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO "user".users (tenant_id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, $3, $4, 'active')
			RETURNING id
		`, tenantID, ui.Email, verifiedAt, displayName).Scan(&userID); err != nil {
			return uuid.Nil, err
		}
	case err != nil:
		return uuid.Nil, err
	default:
		// Adopting an existing account needs four things. First, an address the
		// provider proves, or anyone who gets a provider to emit the victim's
		// address inherits their account.
		if !vouch.proved {
			return uuid.Nil, errs.ErrSocialEmailUnverified
		}
		// Nor is an account adopted on a domain whose organisation requires
		// single sign-on: only its identity provider signs its people in.
		if errors.Is(vouch.refusal, errs.ErrAuthSSORequired) {
			return uuid.Nil, vouch.refusal
		}
		// Second, this tenant must be the account's home. Emails are unique across
		// tenants, so otherwise a tenant admin's own IdP could assert another tenant's
		// user's address, or a guest's, and be handed that user's tokens.
		home, err := identitylink.HomeIn(ctx, tx, userID, tenantID)
		if err != nil {
			return uuid.Nil, err
		}
		if !home {
			return uuid.Nil, errs.ErrSocialAccountNotInTenant
		}
		// Third, the address must be vouched for — proved by the account or its
		// organisation's directory provisioned it — or a squatter who registered
		// it unverified keeps a working password on the adopted account.
		vouched, err := identitylink.AddressVerified(ctx, tx, userID)
		if err != nil {
			return uuid.Nil, err
		}
		if !vouched {
			return uuid.Nil, errs.ErrSocialAccountUnverified
		}
		// Fourth, the account must not administer the organisation, or whoever
		// can configure a provider could assert an owner's address. It keeps its
		// own credentials and connects a provider from the account instead.
		admin, err := identitylink.Administers(ctx, tx, userID, tenantID)
		if err != nil {
			return uuid.Nil, err
		}
		if admin {
			return uuid.Nil, errs.ErrSocialAccountAdministers
		}
		// The provider proved the address, so it is verified from now on.
		if err := identitylink.MarkAddressVerified(ctx, tx, userID); err != nil {
			return uuid.Nil, err
		}
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

// refuseCapturedAccount returns errs.ErrAuthSSORequired when userID's address
// is on a domain whose organisation requires single sign-on and the account
// isn't exempt: social sign-in, whichever provider, never satisfies it.
func (s *Service) refuseCapturedAccount(ctx context.Context, userID uuid.UUID) error {
	if s.capture == nil {
		return nil
	}
	var email string
	if err := s.pool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, userID).Scan(&email); err != nil {
		return err
	}
	return s.capture.RefuseCaptured(ctx, email)
}

// vouching is what a provider's word for an address is worth to a tenant:
// proved reports whether it verifies the address, and refusal, when set, is
// why the provider may not create an account for it.
type vouching struct {
	proved  bool
	refusal error
}

// vouchingFor weighs ui's address for tenantID's provider. An OpenID Connect
// provider's endpoints are the organisation's choice, so it proves only
// addresses on domains the organisation manages; an adapter's are fixed. It
// reads every organisation's domains, so it runs before the transaction.
func (s *Service) vouchingFor(ctx context.Context, tenantID uuid.UUID, provider string, ui userInfo) (vouching, error) {
	v := vouching{proved: ui.EmailVerified}
	domain, managed, err := domainverify.ManagingDomain(postgres.AcrossTenants(ctx), s.pool, ui.Email)
	if err != nil {
		return v, err
	}
	own := managed && domain.TenantID == tenantID
	if adapterKind(provider) == kindOIDC && !own {
		v.proved = false
	}
	if !managed {
		return v, nil
	}
	// A domain that requires single sign-on takes new accounts through it
	// alone, and any other managed domain only from its own organisation.
	if domain.SSO && s.capture != nil {
		err := s.capture.RefuseCaptured(ctx, ui.Email)
		if errors.Is(err, errs.ErrAuthSSORequired) {
			v.refusal = err
			return v, nil
		}
		if err != nil {
			return v, err
		}
	}
	if !own {
		v.refusal = errs.ErrUserDomainManaged
	}
	return v, nil
}

// requireSelfRegistration refuses with ErrAuthSelfRegistrationDisabled unless
// the tenant allows self-registration. No wired policy counts as closed.
func (s *Service) requireSelfRegistration(ctx context.Context, tenantID uuid.UUID) error {
	if s.auth == nil {
		return errs.ErrAuthSelfRegistrationDisabled
	}
	open, err := s.auth.SelfRegistrationEnabled(ctx, tenantID)
	if err != nil {
		return err
	}
	if !open {
		return errs.ErrAuthSelfRegistrationDisabled
	}
	return nil
}

// recordSignUpRefused audits a social sign-up refused because the tenant does
// not allow self-registration, naming the provider and the asserted address so
// an administrator can see who tried to join. Written on its own: the
// provisioning transaction it describes was rolled back.
func (s *Service) recordSignUpRefused(ctx context.Context, tenantID uuid.UUID, provider string, ui userInfo) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorType: "system",
		Action: "social.signup_refused", ResourceType: "tenant", ResourceID: &tid,
		Metadata: map[string]any{
			"provider":       provider,
			"email":          ui.Email,
			"email_verified": ui.EmailVerified,
			"reason":         "self_registration_disabled",
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ExchangeLogin trades a one-time social login code for a Qeet token pair, or
// the second-factor challenge to complete first, while the provider that
// issued it is still on: a code of one since switched off or deleted is refused.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.LoginResult, error) {
	if rawCode == "" {
		return nil, errs.ErrSocialCodeRequired
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
		return nil, errs.ErrSocialLoginCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.UsedAt.Valid {
		return nil, errs.ErrSocialLoginCodeUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errs.ErrSocialLoginCodeExpired
	}
	if !row.Enabled {
		return nil, errs.ErrSocialProviderNotConfigured
	}
	if err := q.MarkSocialLoginCodeUsed(ctx, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.BeginSocialSignIn(ctx, row.UserID, row.TenantID, ip, ua)
}

// Handler serves the social endpoints. CookieSecure marks the SSO and binding
// cookies Secure. LoginBaseURL is the hosted login's origin, where browser
// failures go with a generic error code. PublicBaseURL is this API's public
// origin, or "" to build callback URLs from the request's Host.
type Handler struct {
	Service       *Service
	CookieSecure  bool
	LoginBaseURL  string
	PublicBaseURL string
	// ActOnCheck lets a change of where an OpenID Connect provider finds its
	// keys and claims through only for a caller who outranks every
	// administrator linked to it (rbac CheckActOn). Without it the change is
	// refused while one is linked.
	ActOnCheck identitylink.ActOn
}

// checkTrust refuses pointing the organisation's OpenID Connect provider name
// at discoveryURL, unless that is where it already looks, when the caller may
// not act on every administrator linked to it: the provider signs them in on
// what that URL serves. A provider set up again under a name it had before
// gets its earlier links back, so it counts as a change too.
func (h *Handler) checkTrust(r *http.Request, tenantID uuid.UUID, name, discoveryURL string) error {
	if adapterKind(name) != kindOIDC {
		return nil
	}
	ctx := r.Context()
	var current string
	err := h.Service.pool.QueryRow(ctx, `SELECT coalesce(discovery_url, '') FROM tenant.social_providers WHERE tenant_id = $1 AND provider = $2`,
		tenantID, name).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && strings.TrimSpace(discoveryURL) == current {
		return nil
	}
	return identitylink.CheckTrustChange(ctx, h.Service.pool, httpx.PrincipalFromCtx(ctx), h.ActOnCheck, tenantID, uuid.Nil, name)
}

// Mount registers the social sign-in routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/social/providers", h.upsertProvider)
	r.Patch("/social/providers/{provider}", h.updateProvider)
	r.Delete("/social/providers/{provider}", h.deleteProvider)
	r.Get("/tenants/{tenantID}/social/providers", h.listProviders)
	r.Get("/users/{userID}/social/identities", h.listIdentities)
	r.Delete("/social/identities/{id}", h.unlink)
	// Self-service (tenant-independent): manage the social logins on my own
	// account, so a user who signed up via Google can see/unlink it pre-org.
	r.Get("/me/social/identities", h.listMyIdentities)
	r.Delete("/me/social/identities/{id}", h.unlinkMine)
	// Authenticated "connect this provider to my account" — returns the provider
	// authorize URL for the browser to navigate to. The callback links the
	// identity to the caller (never creates/switches accounts).
	r.Post("/social/{provider}/link/start", h.linkStart)
	r.Post("/social/link/complete", h.linkComplete)
}

// MountPublic mounts the browser-facing OAuth ceremony, which carries no JWT.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/social/{provider}/start", h.start)
	r.Get("/social/{provider}/callback", h.callback)
	r.Post("/social/{provider}/callback", h.callback) // Apple response_mode=form_post
	r.Post("/social/exchange", h.exchange)
	// Which platform (tenant-less) providers are configured — lets the console
	// enable only the social buttons that will actually work.
	r.Get("/social/platform/providers", h.platformProviders)
}

// platformProviders reports the configured platform-level social providers.
func (h *Handler) platformProviders(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"providers": h.Service.PlatformProviderNames()})
}

// callbackURL returns the public callback URL the upstream provider must
// redirect back to; it must match between start and the token exchange.
func (h *Handler) callbackURL(r *http.Request, provider string) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL) + "/v1/social/" + provider + "/callback"
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
	in.ChangedBy = changedBy(r)
	if err := h.checkTrust(r, tenantID, in.Provider, in.DiscoveryURL); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
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
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
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
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
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
	var by user.Remover
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		by.UserID = p.UserID
	}
	by.IP, by.UserAgent, by.RequestID = httpx.ClientIP(r), r.UserAgent(), httpx.RequestID(r)
	// Only an administrator who outranks the account takes a way in from it.
	mayChange := func(owner uuid.UUID) error { return httpx.ActOn(r, h.ActOnCheck, tenantID, owner) }
	if err := h.Service.Unlink(r.Context(), id, tenantID, by, mayChange); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listMyIdentities lists the social logins on the caller's own account (no tenant).
func (h *Handler) listMyIdentities(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.ListIdentitiesForUser(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// linkStart begins an authenticated link ceremony: it stashes the caller in the
// OAuth state and returns the provider's authorize URL for the browser to
// navigate to. Unlike /social/{provider}/start (public login), the callback for
// this ceremony attaches the identity to the caller instead of logging in.
func (h *Handler) linkStart(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	provider := chi.URLParam(r, "provider")
	if !h.Service.PlatformProviderEnabled(provider) {
		httpx.WriteError(w, r, errs.ErrSocialProviderNotConfigured)
		return
	}
	authURL, err := h.Service.BeginPlatformLink(r.Context(), provider, h.callbackURL(r, provider), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorize_url": authURL})
}

type linkCompleteInput struct {
	Code string `json:"code"`
}

// linkComplete attaches the provider a link callback returned (held under the
// link_code the account page was sent back with) to the caller — only when the
// caller is the account that began the link.
func (h *Handler) linkComplete(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in linkCompleteInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	provider, err := h.Service.CompletePlatformLink(r.Context(), in.Code, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"provider": provider})
}

// unlinkMine removes a social login from the caller's own account.
func (h *Handler) unlinkMine(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	by := user.Remover{UserID: p.UserID, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if err := h.Service.UnlinkForUser(r.Context(), id, *p.UserID, by); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// redirectSocialError sends a failed browser-facing ceremony back to the hosted
// login with a generic error code, never the detail, keeping the request's
// return_to so the person can retry. Without LoginBaseURL it writes the error
// as JSON.
func (h *Handler) redirectSocialError(w http.ResponseWriter, r *http.Request, err error) {
	if h.LoginBaseURL == "" {
		// No hosted login app configured — fall back to the JSON error.
		httpx.WriteError(w, r, err)
		return
	}
	q := url.Values{"error": {"social"}}
	// A suspended or deleted account is told so, as at password sign-in, and
	// one that can't be adopted yet is told to verify its address.
	switch {
	case errors.Is(err, errs.ErrAuthAccountInactive):
		q.Set("error", "account_inactive")
	case errors.Is(err, errs.ErrSocialAccountUnverified):
		q.Set("error", "account_unverified")
	}
	if rt := r.URL.Query().Get("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, h.LoginBaseURL+"/sign-in?"+q.Encode(), http.StatusFound)
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
// callback checks. ?tenant=<slug> or ?tenant_id=<uuid> names the organisation
// (none means the console's platform sign-in); ?return_to opts into the hosted
// flow.
func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	tenantRef := r.URL.Query().Get("tenant")
	if tenantRef == "" {
		tenantRef = r.URL.Query().Get("tenant_id")
	}
	// No tenant → platform (tenant-less) console flow. ?intent=signup permits
	// just-in-time account creation; anything else (sign-in) requires an existing
	// account, so a "sign in with Google" can't silently create one.
	if tenantRef == "" {
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
	authURL, err := h.Service.BeginLogin(r.Context(), provider, tenantRef, h.callbackURL(r, provider), r.URL.Query().Get("return_to"))
	if err != nil {
		h.redirectSocialError(w, r, err)
		return
	}
	h.binding().Add(w, r, stateOf(authURL))
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- authorization_endpoint checked by checkAuthorizationEndpoint
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

	// Platform (tenant-less) console sign-in: complete it and bounce the SPA to
	// /sign-in with a one-time code to exchange. Fall through to the tenant flow
	// only when the state isn't a platform state.
	if h.Service.PlatformProviderEnabled(provider) {
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
			return
		}
		// A suspended or deleted account: say so on the console's own sign-in
		// page, not the hosted login's.
		if errors.Is(perr, errs.ErrAuthAccountInactive) {
			http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=account_inactive", http.StatusFound)
			return
		}
		// A sign-in begun in another browser: say so, so the person starts it
		// again here.
		if errors.Is(perr, errs.ErrSocialBrowserMismatch) {
			http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=other_browser", http.StatusFound)
			return
		}
		// Sign-in with a provider that has no account yet: bounce to sign-in with
		// a clear "sign up first" signal instead of silently creating an account.
		if errors.Is(perr, errs.ErrSocialNoAccount) {
			http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=no_account", http.StatusFound)
			return
		}
		// An account uses the address but hasn't proved owning it: say so, so
		// the person verifies it or resets its password first.
		if errors.Is(perr, errs.ErrSocialAccountUnverified) {
			http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=account_unverified", http.StatusFound)
			return
		}
		if !errors.Is(perr, errs.ErrSocialStateInvalid) {
			h.redirectSocialError(w, r, perr)
			return
		}
	}

	res, err := h.Service.CompleteCallback(r.Context(), provider, state, code, startedHere)
	if (errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) || errors.Is(err, errs.ErrSocialBrowserMismatch)) && h.LoginBaseURL != "" {
		// A closed organisation, or a sign-in begun in another browser, not a
		// provider failure: say so, and keep the way back to the application
		// (validated when the sign-in began).
		q := url.Values{"error": {"registration_closed"}}
		if errors.Is(err, errs.ErrSocialBrowserMismatch) {
			q.Set("error", "other_browser")
		}
		if res != nil && res.ReturnTo != "" {
			q.Set("return_to", res.ReturnTo)
		}
		http.Redirect(w, r, h.LoginBaseURL+"/sign-in?"+q.Encode(), http.StatusFound)
		return
	}
	if err != nil {
		h.redirectSocialError(w, r, err)
		return
	}
	h.binding().Remove(w, r, state)
	if res.ReturnTo != "" {
		// An address the organisation refuses is told so on the hosted login,
		// as every other method is, not shown a provider failure.
		if aerr := h.Service.CheckHostedSignIn(r.Context(), res.TenantID, res.UserID, httpx.ClientIP(r)); aerr != nil {
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
		if c, cerr := r.Cookie(auth.TrustedDeviceCookie); cerr == nil {
			trusted = c.Value
		}
		ls, serr := h.Service.BeginLoginSession(r.Context(), res.UserID, res.TenantID, httpx.ClientIP(r), r.UserAgent(),
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
		auth.SetLoginSessionCookie(w, ls.RawCookie, h.CookieSecure)
		http.Redirect(w, r, res.ReturnTo, http.StatusFound)
		return
	}
	target := h.Service.appBaseURL + "/auth/social/callback?code=" + url.QueryEscape(res.Code)
	http.Redirect(w, r, target, http.StatusFound)
}

type exchangeInput struct {
	Code string `json:"code"`
}

// challengeFragment encodes a hosted social sign-in's second-factor challenge
// for the hosted login's URL fragment: mfa_token, methods, factors (JSON, as a
// password sign-in lists them) and, for an enrolment, enrollment_required and
// enrollment_due_at.
func challengeFragment(c auth.MFAChallenge) string {
	v := url.Values{"mfa_token": {c.MFAToken}, "methods": {strings.Join(c.Methods, ",")}}
	if len(c.Factors) > 0 {
		if factors, err := json.Marshal(c.Factors); err == nil {
			v.Set("factors", string(factors))
		}
	}
	if c.EnrollmentRequired {
		v.Set("enrollment_required", "true")
		if c.EnrollmentDueAt != nil {
			v.Set("enrollment_due_at", c.EnrollmentDueAt.UTC().Format(time.RFC3339))
		}
	}
	return v.Encode()
}

// writeSignIn answers a social code exchange: the token pair, or the
// second-factor challenge shaped as a password sign-in's, met at /v1/auth/mfa.
func writeSignIn(w http.ResponseWriter, res *auth.LoginResult) {
	if res.MFARequired {
		httpx.WriteJSON(w, http.StatusOK, res.Body())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Pair)
}

// exchange trades a one-time social login code for a token pair.
func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var in exchangeInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Platform (tenant-less) code first; fall back to the tenant exchange when
	// the code isn't a platform one.
	if res, perr := h.Service.ExchangePlatformLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent()); perr == nil {
		writeSignIn(w, res)
		return
	} else if !errors.Is(perr, errs.ErrSocialLoginCodeInvalid) {
		httpx.WriteError(w, r, perr)
		return
	}
	res, err := h.Service.ExchangeLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	writeSignIn(w, res)
}

// requireVerifiedAddress refuses, with ErrSocialAccountUnverified, adopting an
// account whose address nobody has proved owning.
func requireVerifiedAddress(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID uuid.UUID) error {
	var verified bool
	if err := db.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM "user".users WHERE id = $1`, userID).Scan(&verified); err != nil {
		return err
	}
	if !verified {
		return errs.ErrSocialAccountUnverified
	}
	return nil
}
