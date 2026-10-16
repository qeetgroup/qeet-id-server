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
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
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
	egress     *egress.Policy
	box        *envelope.Cipher
	// platform holds tenant-less social providers for the console's own Qeet ID
	// sign-in (env-configured, e.g. Google). Distinct from the per-tenant
	// social_providers table used for tenants' end users. See platform.go.
	platform map[string]providerConfig
	// returnOrigins is the allowlist for the hosted flow's `return_to`, keyed by
	// normalized "scheme://host[:port]". Empty means only root-relative paths
	// are accepted. See SetAllowedReturnOrigins and validateReturnTo.
	returnOrigins map[string]struct{}
}

// SetAllowedReturnOrigins declares the origins a `return_to` may point at.
// Wired from the composition root with the app + hosted-login base URLs and the
// configured browser origins, which are already validated (production refuses to
// start with a wildcard).
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

// validateReturnTo rejects a `return_to` that would send the browser somewhere
// we do not control.
//
// The callback sets the hosted-login SSO cookie and THEN redirects here, so an
// unvalidated value is an open redirect on the authentication domain: an
// attacker sends a victim to /v1/social/google/start?return_to=https://evil… and
// the victim lands on the attacker's page having just authenticated, from a
// first-party origin. The hosted flow only ever needs to return to the login or
// console app.
//
// Accepted: "" (non-hosted flow), a root-relative path, or an absolute URL whose
// origin is allowlisted. A protocol-relative "//evil.example" is rejected — it
// looks relative but is not.
func (s *Service) validateReturnTo(returnTo string) error {
	if returnTo == "" {
		return nil
	}
	if strings.HasPrefix(returnTo, "//") || strings.HasPrefix(returnTo, `/\`) {
		return errs.ErrSocialReturnToInvalid
	}
	if strings.HasPrefix(returnTo, "/") {
		return nil
	}
	origin := normalizeOrigin(returnTo)
	if origin == "" {
		return errs.ErrSocialReturnToInvalid
	}
	if _, ok := s.returnOrigins[origin]; !ok {
		return errs.ErrSocialReturnToInvalid
	}
	return nil
}

func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

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

type CreateProviderInput struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Provider     string    `json:"provider"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	DiscoveryURL string    `json:"discovery_url"`
}

func (s *Service) UpsertProvider(ctx context.Context, in CreateProviderInput) (*Provider, error) {
	if _, err := s.egress.ValidateHTTPURL(in.DiscoveryURL); err != nil {
		return nil, errs.ErrSocialProviderNoDiscovery
	}
	if s.box == nil {
		return nil, errs.ErrInternalServer.WithDetail("social provider secret encryption is unavailable")
	}
	ciphertext, nonce, err := s.box.Seal(in.TenantID, "social-provider", in.Provider, []byte(in.ClientSecret))
	if err != nil {
		return nil, err
	}
	var r struct {
		ID                 uuid.UUID
		TenantID           uuid.UUID
		Provider, ClientID string
		DiscoveryURL       *string
		Enabled            bool
		CreatedAt          time.Time
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO tenant.social_providers
		    (tenant_id, provider, client_id, client_secret, client_secret_ct,
		     client_secret_nonce, encryption_version, discovery_url)
		VALUES ($1, $2, $3, '', $4, $5, 1, NULLIF($6, ''))
		ON CONFLICT (tenant_id, provider) DO UPDATE SET
		    client_id = EXCLUDED.client_id,
		    client_secret = '',
		    client_secret_ct = EXCLUDED.client_secret_ct,
		    client_secret_nonce = EXCLUDED.client_secret_nonce,
		    encryption_version = 1,
		    discovery_url = EXCLUDED.discovery_url,
		    enabled = TRUE
		RETURNING id, tenant_id, provider, client_id, discovery_url, enabled, created_at
	`, in.TenantID, in.Provider, in.ClientID, ciphertext, nonce, in.DiscoveryURL).Scan(
		&r.ID, &r.TenantID, &r.Provider, &r.ClientID, &r.DiscoveryURL, &r.Enabled, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	p := Provider{
		ID:           r.ID,
		TenantID:     r.TenantID,
		Provider:     r.Provider,
		ClientID:     r.ClientID,
		DiscoveryURL: r.DiscoveryURL,
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

// UnlinkForUser removes one of the caller's connected platform social accounts.
func (s *Service) UnlinkForUser(ctx context.Context, id, userID uuid.UUID) error {
	n, err := s.q.DeletePlatformSocialIdentityForUser(ctx, dbgen.DeletePlatformSocialIdentityForUserParams{
		ID:     id,
		UserID: userID,
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

// providerConfig is the stored config for one provider. For discovery-based
// OIDC providers (google, microsoft, tenant providers) discoveryURL is set and
// kind is "oidc"/""; GitHub isn't OIDC so kind is "github" and it uses a
// dedicated adapter (github.go) with hardcoded endpoints instead.
type providerConfig struct {
	clientID     string
	clientSecret string
	discoveryURL string
	kind         string
	// Apple only (kind == "apple"): the client secret is a short-lived ES256 JWT
	// derived from these, not a static string.
	teamID     string
	keyID      string
	privateKey string
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

// loadProvider returns an enabled, discovery-based provider config for a tenant.
func (s *Service) loadProvider(ctx context.Context, tenantID uuid.UUID, provider string) (providerConfig, error) {
	var pc providerConfig
	var enabled bool
	var clientID, legacySecret string
	var discoveryURL *string
	var ciphertext, nonce []byte
	err := s.pool.QueryRow(ctx, `
		SELECT client_id, client_secret, client_secret_ct, client_secret_nonce,
		       discovery_url, enabled
		FROM tenant.social_providers
		WHERE tenant_id = $1 AND provider = $2
	`, tenantID, provider).Scan(&clientID, &legacySecret, &ciphertext, &nonce, &discoveryURL, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return pc, errs.ErrSocialProviderNotConfigured
	}
	if err != nil {
		return pc, err
	}
	if !enabled {
		return pc, errs.ErrSocialProviderDisabled
	}
	if discoveryURL == nil || *discoveryURL == "" {
		return pc, errs.ErrSocialProviderNoDiscovery
	}
	pc.clientID = clientID
	pc.discoveryURL = *discoveryURL
	if len(ciphertext) > 0 {
		if s.box == nil {
			return pc, errs.ErrSocialProviderNotConfigured
		}
		plain, openErr := s.box.Open(tenantID, "social-provider", provider, ciphertext, nonce)
		if openErr != nil {
			return pc, openErr
		}
		pc.clientSecret = string(plain)
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
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return "", errs.ErrSocialDiscoveryFailed.Wrap(err)
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

	pc, err := s.loadProvider(ctx, st.TenantID, provider)
	if err != nil {
		return nil, err
	}
	doc, err := s.oauth.discovery(ctx, pc.discoveryURL)
	if err != nil {
		return nil, errs.ErrSocialDiscoveryFailed.Wrap(err)
	}
	accessToken, err := s.oauth.exchange(ctx, doc, pc.clientID, pc.clientSecret, code, st.RedirectUri, st.CodeVerifier)
	if err != nil {
		return nil, errs.ErrSocialTokenExchangeFailed.Wrap(err)
	}
	ui, err := s.oauth.userinfo(ctx, doc, accessToken)
	if err != nil {
		return nil, errs.ErrSocialUserinfoFailed.Wrap(err)
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
		if err := s.requireSelfRegistration(ctx, tenantID); err != nil {
			return uuid.Nil, err
		}
		// Provisioning a fresh account. An unverified assertion may *name* the
		// account — refusing would lock out every provider that omits the claim
		// — but it must not mark the address verified. Other flows treat a
		// verified address as proof of control, so the provider's word is only
		// carried through when the provider actually vouched for it.
		//
		// Written as raw SQL rather than InsertUserWithEmail because that query
		// hardcodes email_verified_at = NOW(); fold this parameter into
		// queries.sql at the next `sqlc generate`.
		var displayName *string
		if ui.Name != "" {
			displayName = &ui.Name
		}
		var verifiedAt *time.Time
		if ui.EmailVerified {
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
		// Adopting an account that already exists. Two things have to hold.
		//
		// First, the assertion must be verified: otherwise anyone who can
		// persuade a provider to emit the victim's address inherits their
		// account.
		if !ui.EmailVerified {
			return uuid.Nil, errs.ErrSocialEmailUnverified
		}
		// Second — and this is the one a verified assertion does NOT cover —
		// the account must already belong to the tenant this login is for.
		// Emails are globally unique platform-wide (migration 0022), so
		// GetUserByEmail above can return a user owned by a completely
		// different tenant. Without this check, a tenant admin could register
		// an IdP they control, assert another tenant's user's address with
		// email_verified=true, and be handed a token pair carrying that user's
		// id — enough to change their password, read their profile, and
		// switch-tenant into their org.
		belongs, err := userInTenant(ctx, tx, userID, tenantID)
		if err != nil {
			return uuid.Nil, err
		}
		if !belongs {
			return uuid.Nil, errs.ErrSocialAccountNotInTenant
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

// ExchangeLogin trades a one-time social login code for a Qeet token pair.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
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
	// Self-service (tenant-independent): manage the social logins on my own
	// account, so a user who signed up via Google can see/unlink it pre-org.
	r.Get("/me/social/identities", h.listMyIdentities)
	r.Delete("/me/social/identities/{id}", h.unlinkMine)
	// Authenticated "connect this provider to my account" — returns the provider
	// authorize URL for the browser to navigate to. The callback links the
	// identity to the caller (never creates/switches accounts).
	r.Post("/social/{provider}/link/start", h.linkStart)
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
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
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
	authURL, err := h.Service.BeginPlatformLink(r.Context(), provider, callbackURL(r, provider), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorize_url": authURL})
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
	if err := h.Service.UnlinkForUser(r.Context(), id, *p.UserID); err != nil {
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
	// No tenant → platform (tenant-less) console flow. ?intent=signup permits
	// just-in-time account creation; anything else (sign-in) requires an existing
	// account, so a "sign in with Google" can't silently create one.
	if tenantRef == "" {
		allowCreate := r.URL.Query().Get("intent") == "signup"
		authURL, err := h.Service.BeginPlatformLogin(r.Context(), provider, callbackURL(r, provider), allowCreate)
		if err != nil {
			h.redirectSocialError(w, r, err)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
		return
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
	// Apple uses response_mode=form_post (params in the POST body); the other
	// providers use a GET query. r.FormValue reads whichever applies.
	if r.Method == http.MethodPost {
		if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
			h.redirectSocialError(w, r, err)
			return
		}
	}
	state, code := r.FormValue("state"), r.FormValue("code")

	// Platform (tenant-less) console sign-in: complete it and bounce the SPA to
	// /sign-in with a one-time code to exchange. Fall through to the tenant flow
	// only when the state isn't a platform state.
	if h.Service.PlatformProviderEnabled(provider) {
		res, perr := h.Service.CompletePlatformCallback(r.Context(), provider, state, code)
		if perr == nil {
			if res.Linked {
				// Authenticated link ceremony: no session issued — return to the
				// account page where the newly-connected provider now shows.
				http.Redirect(w, r, h.Service.appBaseURL+"/account/security?linked="+url.QueryEscape(res.Provider), http.StatusFound)
			} else {
				http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_code="+url.QueryEscape(res.LoginCode), http.StatusFound)
			}
			return
		}
		// A link that collided with another account: send the user back to the
		// account page with a clear error rather than the login app.
		if errors.Is(perr, errs.ErrSocialAlreadyLinked) {
			http.Redirect(w, r, h.Service.appBaseURL+"/account/security?link_error=already_linked", http.StatusFound)
			return
		}
		// Sign-in with a provider that has no account yet: bounce to sign-in with
		// a clear "sign up first" signal instead of silently creating an account.
		if errors.Is(perr, errs.ErrSocialNoAccount) {
			http.Redirect(w, r, h.Service.appBaseURL+"/sign-in?social_error=no_account", http.StatusFound)
			return
		}
		if !errors.Is(perr, errs.ErrSocialStateInvalid) {
			h.redirectSocialError(w, r, perr)
			return
		}
	}

	res, err := h.Service.CompleteCallback(r.Context(), provider, state, code)
	if errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) && h.LoginBaseURL != "" {
		// A closed organisation, not a provider failure: say so, and keep the
		// way back to the application (validated when the sign-in began).
		q := url.Values{"error": {"registration_closed"}}
		if res != nil && res.ReturnTo != "" {
			q.Set("return_to", res.ReturnTo)
		}
		http.Redirect(w, r, h.LoginBaseURL+"/login?"+q.Encode(), http.StatusFound)
		return
	}
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
	// Platform (tenant-less) code first; fall back to the tenant exchange when
	// the code isn't a platform one.
	if pair, perr := h.Service.ExchangePlatformLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent()); perr == nil {
		httpx.WriteJSON(w, http.StatusOK, pair)
		return
	} else if !errors.Is(perr, errs.ErrSocialLoginCodeInvalid) {
		httpx.WriteError(w, r, perr)
		return
	}
	pair, err := h.Service.ExchangeLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

// userInTenant reports whether a user is one this tenant can sign in.
//
// Two things count: the user's home tenant (users.tenant_id, which is what a
// social-provisioned user gets and what a repeat login has to match), and an
// rbac.user_roles grant (which is how a guest becomes a member). Requiring only
// the latter would reject a user this very flow provisioned, since provisioning
// grants no role.
func userInTenant(ctx context.Context, tx pgx.Tx, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM "user".users u
			WHERE u.id = $1 AND u.deleted_at IS NULL AND u.tenant_id = $2
			UNION ALL
			SELECT 1 FROM rbac.user_roles ur
			WHERE ur.user_id = $1 AND ur.tenant_id = $2
		)
	`, userID, tenantID).Scan(&ok)
	return ok, err
}
