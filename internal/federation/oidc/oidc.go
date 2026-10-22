// Package oidc implements Qeet's OpenID Connect provider role: the OAuth2/OIDC
// grants (authorization_code+PKCE, refresh, client_credentials, token-exchange,
// device, CIBA) plus discovery, JWKS, and userinfo endpoints.
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

type Client struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	ClientID       string    `json:"client_id"`
	Type           string    `json:"type"`
	Name           string    `json:"name"`
	RedirectURIs   []string  `json:"redirect_uris"`
	PostLogoutURIs []string  `json:"post_logout_uris"`
	GrantTypes     []string  `json:"grant_types"`
	Scopes         []string  `json:"scopes"`
	CreatedAt      time.Time `json:"created_at"`
	// PKCEExemptUntil is when this confidential application's exemption from
	// sending a PKCE code_challenge (and a nonce) ends; nil: no exemption.
	PKCEExemptUntil *time.Time `json:"pkce_exempt_until"`
	// BackchannelLogoutURI receives a signed logout token, server to server,
	// when someone it signed in signs out; FrontchannelLogoutURI is loaded by
	// the hosted signed-out page. "" for none.
	BackchannelLogoutURI  string `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`
}

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
	// notifier delivers the CIBA async consent prompt (nil = no notification;
	// the user must know to check pending requests themselves). See ciba.go.
	notifier Notifier
	// limits gates application (relying-party) registration by plan (nil = off).
	limits PlanLimiter
	// grantMaxAge ends a grant that long after it starts however often it is
	// renewed, where its organisation sets no maximum session age of its own.
	grantMaxAge time.Duration
	// addresses is the organisations' address rules (nil = no rules). See
	// address.go.
	addresses AddressPolicy
	// lockout bounds wrong application secrets. See client_lockout.go.
	lockout ClientLockout
	// logoutClient sends back-channel sign-out notices under logoutEgress
	// (the SSRF guard); nil sends none. See logout.go.
	logoutClient *http.Client
	logoutEgress *egress.Policy
	// exchangeMaxDepth bounds a chain of token exchanges (config
	// TOKEN_EXCHANGE_MAX_DEPTH).
	exchangeMaxDepth int
	// agentStatus returns an AI agent's lifecycle status, so introspection
	// reports a suspended agent's tokens inactive (nil: not checked).
	agentStatus func(ctx context.Context, agentID uuid.UUID) (string, error)
}

// SetAgentStatus wires the agent lifecycle lookup introspection consults.
func (s *Service) SetAgentStatus(f func(ctx context.Context, agentID uuid.UUID) (string, error)) {
	s.agentStatus = f
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer, grantMaxAge: 30 * 24 * time.Hour, lockout: DefaultClientLockout(), exchangeMaxDepth: 2}
}

// SetTokenExchangeMaxDepth sets how many exchanges deep a token may be
// exchanged again (at least 1).
func (s *Service) SetTokenExchangeMaxDepth(n int) {
	if n < 1 {
		n = 1
	}
	s.exchangeMaxDepth = n
}

// SetGrantMaxAge sets how long an application's grant lasts however often it is
// renewed, where its organisation sets no maximum session age (config
// SESSION_MAX_AGE).
func (s *Service) SetGrantMaxAge(d time.Duration) { s.grantMaxAge = d }

// PlanLimiter returns the numeric cap for a plan-gated resource (negative =
// unlimited). Satisfied by operations/entitlements.Service, injected via
// SetPlanLimiter.
type PlanLimiter interface {
	Limit(ctx context.Context, tenantID uuid.UUID, resource string) (int, error)
}

// SetPlanLimiter wires the plan-limit checker (nil disables the gate).
func (s *Service) SetPlanLimiter(l PlanLimiter) { s.limits = l }

// CountClients returns the tenant's number of registered applications (relying
// parties) — the "apps" limit value, surfaced as usage in billing.
func (s *Service) CountClients(ctx context.Context, tenantID uuid.UUID) (int, error) {
	n, err := s.q.CountOIDCClientsByTenant(ctx, tenantID)
	return int(n), err
}

type CreateClientInput struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	RedirectURIs   []string  `json:"redirect_uris"`
	PostLogoutURIs []string  `json:"post_logout_uris"`
	GrantTypes     []string  `json:"grant_types"`
	Scopes         []string  `json:"scopes"`
	// Where the application hears of a sign-out (see Client).
	BackchannelLogoutURI  string `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`
}

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an OIDC mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) RegisterClient(ctx context.Context, tx pgx.Tx, in CreateClientInput) (*Client, string, error) {
	// Plan gate: refuse once the tenant's plan cap for applications is reached.
	if s.limits != nil {
		lim, err := s.limits.Limit(ctx, in.TenantID, "apps")
		if err != nil {
			return nil, "", err
		}
		if lim >= 0 {
			n, err := s.q.WithTx(tx).CountOIDCClientsByTenant(ctx, in.TenantID)
			if err != nil {
				return nil, "", err
			}
			if int(n) >= lim {
				return nil, "", errs.ErrPlanLimit.WithMetadata(map[string]any{"resource": "apps", "limit": lim})
			}
		}
	}
	if in.Type == "" {
		in.Type = "confidential"
	}
	if len(in.GrantTypes) == 0 {
		in.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "profile", "email"}
	}
	if err := validateClientInput(in); err != nil {
		return nil, "", err
	}
	// The columns are NOT NULL DEFAULT '{}'; a nil Go slice encodes as SQL NULL,
	// so coalesce to empty to honour callers that omit these arrays.
	if in.RedirectURIs == nil {
		in.RedirectURIs = []string{}
	}
	if in.PostLogoutURIs == nil {
		in.PostLogoutURIs = []string{}
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
	q := s.q.WithTx(tx)
	row, err := q.InsertOIDCClient(ctx, dbgen.InsertOIDCClientParams{
		TenantID:              in.TenantID,
		ClientID:              clientID,
		ClientSecretHash:      secretHash,
		Type:                  in.Type,
		Name:                  in.Name,
		RedirectUris:          in.RedirectURIs,
		PostLogoutUris:        in.PostLogoutURIs,
		GrantTypes:            in.GrantTypes,
		Scopes:                in.Scopes,
		BackchannelLogoutUri:  in.BackchannelLogoutURI,
		FrontchannelLogoutUri: in.FrontchannelLogoutURI,
	})
	if err != nil {
		return nil, "", err
	}
	c := Client{
		ID: row.ID, TenantID: row.TenantID, ClientID: row.ClientID,
		Type: row.Type, Name: row.Name,
		RedirectURIs: row.RedirectUris, PostLogoutURIs: row.PostLogoutUris,
		GrantTypes: row.GrantTypes, Scopes: row.Scopes, CreatedAt: row.CreatedAt,
		PKCEExemptUntil:      timePtr(row.PkceExemptUntil),
		BackchannelLogoutURI: derefStr(row.BackchannelLogoutUri), FrontchannelLogoutURI: derefStr(row.FrontchannelLogoutUri),
	}
	return &c, raw, nil
}

var supportedClientGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
	"client_credentials": {},
	"token_exchange":     {},
	"urn:ietf:params:oauth:grant-type:device_code":    {},
	"urn:ietf:params:oauth:grant-type:token-exchange": {},
	"urn:openid:params:grant-type:ciba":               {},
}

func validateClientInput(in CreateClientInput) error {
	if in.Type != "public" && in.Type != "confidential" {
		return errs.ErrBadRequest.WithDetail("type must be public or confidential")
	}
	for _, grantType := range in.GrantTypes {
		if _, ok := supportedClientGrantTypes[grantType]; !ok {
			return errs.ErrOIDCGrantTypeUnsupported.WithDetail("unsupported grant_type: " + grantType)
		}
	}
	if in.Type == "public" && containsAny(in.GrantTypes, "token_exchange", grantTypeTokenExchange, grantTypeCIBA) {
		return errs.ErrOIDCUnsupportedFlow
	}
	if !validLogoutURI(in.BackchannelLogoutURI) || !validLogoutURI(in.FrontchannelLogoutURI) {
		return errs.ErrBadRequest.WithDetail("logout URIs must be absolute http(s) URLs without a fragment")
	}
	if contains(in.GrantTypes, "authorization_code") && len(in.RedirectURIs) == 0 {
		return errs.ErrOIDCRedirectURIInvalid.WithDetail("authorization_code clients require a redirect URI")
	}
	for _, raw := range append(append([]string(nil), in.RedirectURIs...), in.PostLogoutURIs...) {
		if err := validateRegisteredRedirectURI(raw); err != nil {
			return err
		}
	}
	return nil
}

// validateRegisteredRedirectURI accepts the redirect forms RFC 8252 allows: an
// HTTPS URL, an HTTP loopback URL or a private-use scheme. A fragment or
// userinfo component is always rejected.
func validateRegisteredRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.User != nil || u.Fragment != "" {
		return errs.ErrOIDCRedirectURIInvalid.WithDetail("redirect URI must be an absolute URI without userinfo or fragment")
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "https":
		if u.Hostname() == "" {
			break
		}
		return nil
	case "http":
		// Loopback only. RFC 8252 §8.3 prefers a literal address because
		// "localhost" can resolve to a non-loopback interface, but rejecting it
		// outright would break local development, so both are accepted.
		host := strings.ToLower(u.Hostname())
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	default:
		// Private-use scheme, e.g. "com.example.app:/oauth2redirect". RFC 8252
		// §7.1 requires a reverse-DNS-style scheme the app controls, so insist
		// on a dot and reject anything resembling a network scheme.
		if isPrivateUseScheme(scheme) {
			return nil
		}
	}
	return errs.ErrOIDCRedirectURIInvalid.WithDetail(
		"redirect URI must use HTTPS, an HTTP loopback IP, or a reverse-DNS private-use scheme")
}

// reservedRedirectSchemes are network schemes a client must never register as
// a private-use redirect, even though some contain a dot.
var reservedRedirectSchemes = map[string]struct{}{
	"http": {}, "https": {}, "ftp": {}, "file": {}, "data": {},
	"javascript": {}, "ws": {}, "wss": {}, "mailto": {}, "blob": {},
}

func isPrivateUseScheme(scheme string) bool {
	if _, reserved := reservedRedirectSchemes[scheme]; reserved {
		return false
	}
	// Must look like a domain the app owns, reversed: at least one dot, and no
	// leading/trailing/doubled separators.
	if !strings.Contains(scheme, ".") || strings.HasPrefix(scheme, ".") ||
		strings.HasSuffix(scheme, ".") || strings.Contains(scheme, "..") {
		return false
	}
	for _, char := range scheme {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') ||
			char == '.' || char == '-' || char == '+' {
			continue
		}
		return false
	}
	return true
}

// ShadowAICandidate is an unreviewed OIDC client that can act unattended
// (client_credentials or token exchange). LiveGrants counts its active refresh
// tokens.
type ShadowAICandidate struct {
	ID         uuid.UUID `json:"id"`
	ClientID   string    `json:"client_id"`
	Name       string    `json:"name"`
	GrantTypes []string  `json:"grant_types"`
	LiveGrants int       `json:"live_grants"`
	CreatedAt  time.Time `json:"created_at"`
}

// machineGrantTypes are the grant types that let a client obtain a token
// without a human present in the loop.
var machineGrantTypes = []string{"client_credentials", grantTypeTokenExchange}

// ShadowAICandidates lists tenantID's unreviewed OIDC clients whose
// grant_types include a machine grant type, ordered by live-grant count so
// the ones actually in active use surface first.
func (s *Service) ShadowAICandidates(ctx context.Context, tenantID uuid.UUID) ([]ShadowAICandidate, error) {
	rows, err := s.q.ListShadowAICandidates(ctx, dbgen.ListShadowAICandidatesParams{
		TenantID:          tenantID,
		MachineGrantTypes: machineGrantTypes,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ShadowAICandidate, len(rows))
	for i, r := range rows {
		out[i] = ShadowAICandidate{
			ID: r.ID, ClientID: r.ClientID, Name: r.Name,
			GrantTypes: r.GrantTypes, LiveGrants: int(r.LiveGrants),
			CreatedAt: r.CreatedAt,
		}
	}
	return out, nil
}

// ReviewShadowAIClient acknowledges a shadow-AI candidate, dropping it off
// ShadowAICandidates until/unless its grant_types change again.
func (s *Service) ReviewShadowAIClient(ctx context.Context, tenantID, id, reviewerUserID uuid.UUID) error {
	n, err := s.q.ReviewOIDCClient(ctx, dbgen.ReviewOIDCClientParams{
		ReviewedBy: pgtype.UUID{Bytes: reviewerUserID, Valid: true},
		ID:         id,
		TenantID:   tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrOIDCClientNotFound
	}
	return nil
}

// Authorize validates an authorization request for an authenticated user and
// returns a one-time authorization code and the client's tenant ID. The code is
// tied to no hosted-login session, so organisations with address rules refuse
// it; the browser flow uses AuthorizeInLoginSession.
func (s *Service) Authorize(ctx context.Context, userID uuid.UUID, clientID, redirectURI string, scopes []string, nonce, challenge, challengeMethod string) (string, uuid.UUID, error) {
	return s.AuthorizeInLoginSession(ctx, AuthorizeInput{
		UserID: userID, ClientID: clientID, RedirectURI: redirectURI, Scopes: scopes,
		Nonce: nonce, CodeChallenge: challenge, CodeChallengeMethod: challengeMethod,
	})
}

// AuthorizeInput is one authorization request to mint a code for.
type AuthorizeInput struct {
	// LoginSessionID is the hosted-login session the code is minted in
	// (uuid.Nil for none); signing out of it ends the code and its grant.
	LoginSessionID, UserID             uuid.UUID
	ClientID, RedirectURI              string
	Scopes                             []string
	Nonce                              string
	CodeChallenge, CodeChallengeMethod string
	// IP is the browser's address (httpx.ClientIP), which the organisation's
	// address rules must allow.
	IP string
	// Resource ("" for none) is the RFC 8707 resource the token is for, which
	// the organisation must have registered; the code carries it.
	Resource string
	// AuthTime is when the person signed in (zero: unknown); the ID token
	// reports it as auth_time.
	AuthTime time.Time
}

// AuthorizeInLoginSession mints a code for a request in a hosted-login session.
func (s *Service) AuthorizeInLoginSession(ctx context.Context, in AuthorizeInput) (string, uuid.UUID, error) {
	clientID, redirectURI, scopes := in.ClientID, in.RedirectURI, in.Scopes
	userID, loginSessionID := in.UserID, in.LoginSessionID
	nonce, challenge, challengeMethod, ip, resource := in.Nonce, in.CodeChallenge, in.CodeChallengeMethod, in.IP, in.Resource
	info, err := s.q.GetClientRedirectInfo(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrOIDCClientUnknown
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	member, err := s.activeClientTenantMember(ctx, userID, clientID)
	if err != nil {
		return "", uuid.Nil, err
	}
	if !member {
		return "", uuid.Nil, errs.ErrOIDCUserTenantMismatch
	}
	if !contains(info.RedirectUris, redirectURI) {
		return "", uuid.Nil, errs.ErrOIDCRedirectURIInvalid
	}
	for _, sc := range scopes {
		if !contains(info.Scopes, sc) {
			return "", uuid.Nil, errs.ErrOIDCScopeNotPermitted
		}
	}
	if err := validateSignInRequest(info.Type, info.PkceExempt, scopes, nonce, challenge, challengeMethod); err != nil {
		return "", uuid.Nil, err
	}
	if err := s.checkResource(ctx, info.TenantID, resource); err != nil {
		return "", uuid.Nil, err
	}
	// This is where the person signs in to the application, from the browser.
	if err := s.checkAddress(ctx, info.TenantID, userID, ip, "oidc_authorize"); err != nil {
		return "", uuid.Nil, err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", uuid.Nil, err
	}
	err = s.q.InsertAuthorizationCode(ctx, dbgen.InsertAuthorizationCodeParams{
		CodeHash:            hash,
		ClientID:            clientID,
		UserID:              userID,
		TenantID:            info.TenantID,
		RedirectUri:         redirectURI,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		LoginSessionID:      optionalUUID(loginSessionID),
		Resource:            resource,
		AuthTime:            optionalTime(in.AuthTime),
	})
	if err != nil {
		return "", uuid.Nil, err
	}
	return raw, info.TenantID, nil
}

func validPKCEValue(value string, minLength, maxLength int) bool {
	if len(value) < minLength || len(value) > maxLength {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '.' || char == '_' || char == '~' {
			continue
		}
		return false
	}
	return true
}

func (s *Service) activeClientTenantMember(ctx context.Context, userID uuid.UUID, clientID string) (bool, error) {
	var member bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM auth.oidc_clients c
			JOIN tenant.tenants t ON t.id = c.tenant_id
			JOIN rbac.user_roles ur ON ur.tenant_id = c.tenant_id AND ur.user_id = $1
			JOIN "user".users u ON u.id = ur.user_id
			WHERE c.client_id = $2
			  AND t.status = 'active' AND t.deleted_at IS NULL
			  AND u.status = 'active' AND u.deleted_at IS NULL
		)
	`, userID, clientID).Scan(&member)
	return member, err
}

// tokenSubjectLive reports whether what an access token acts for still holds:
// its user active, not deleted and a member of its organisation (itself
// active), and its agent, if any, active.
func (s *Service) tokenSubjectLive(ctx context.Context, claims *tokens.Claims) (bool, error) {
	if claims.UserID != uuid.Nil {
		var member bool
		if err := s.pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM "user".users u
				JOIN rbac.user_roles ur ON ur.user_id = u.id AND ur.tenant_id = $2
				JOIN tenant.tenants t ON t.id = ur.tenant_id
				WHERE u.id = $1
				  AND u.status = 'active' AND u.deleted_at IS NULL
				  AND t.status = 'active' AND t.deleted_at IS NULL
			)
		`, claims.UserID, claims.TenantID).Scan(&member); err != nil {
			return false, err
		}
		if !member {
			return false, nil
		}
	}
	if claims.AgentID != "" && s.agentStatus != nil {
		id, err := uuid.Parse(claims.AgentID)
		if err != nil {
			return false, nil
		}
		status, err := s.agentStatus(ctx, id)
		if err != nil || status != "active" {
			return false, err
		}
	}
	return true, nil
}

// RegisteredRedirect reports whether redirectURI is registered for the client.
// The authorize endpoint uses it to decide whether a failure can be reported to
// the relying party or has to be rendered here.
func (s *Service) RegisteredRedirect(ctx context.Context, clientID, redirectURI string) bool {
	if clientID == "" || redirectURI == "" {
		return false
	}
	info, err := s.q.GetClientRedirectInfo(ctx, clientID)
	if err != nil {
		return false
	}
	return contains(info.RedirectUris, redirectURI)
}

// activeTenantPrincipal reports whether userID and tenantID are both active and
// not deleted, so the user may receive a token for that tenant. Each flow checks
// membership separately.
func (s *Service) activeTenantPrincipal(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var live bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM "user".users u
			JOIN tenant.tenants t ON t.id = $2
			WHERE u.id = $1
			  AND u.status = 'active' AND u.deleted_at IS NULL
			  AND t.status = 'active' AND t.deleted_at IS NULL
		)
	`, userID, tenantID).Scan(&live)
	return live, err
}

// ClientName resolves a client's display name and tenant from its client_id —
// used to render the hosted login/consent screens. Returns ErrNotFound for an
// unknown client.
func (s *Service) ClientName(ctx context.Context, clientID string) (name string, tenantID uuid.UUID, err error) {
	row, err := s.q.GetClientName(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrOIDCClientNotFound
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	return row.Name, row.TenantID, nil
}

// ValidatePostLogoutRedirect reports whether uri is one of the client's
// registered post-logout redirect URIs (RP-Initiated Logout).
func (s *Service) ValidatePostLogoutRedirect(ctx context.Context, clientID, uri string) (bool, error) {
	uris, err := s.q.GetClientPostLogoutURIs(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return contains(uris, uri), nil
}

// ClientTenant is the organisation that owns the application clientID;
// ErrOIDCClientUnknown when none does.
func (s *Service) ClientTenant(ctx context.Context, clientID string) (uuid.UUID, error) {
	info, err := s.q.GetClientRedirectInfo(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrOIDCClientUnknown
	}
	if err != nil {
		return uuid.Nil, err
	}
	return info.TenantID, nil
}

// RegisteredClient reports whether clientID names a registered application.
func (s *Service) RegisteredClient(ctx context.Context, clientID string) bool {
	_, err := s.q.GetClientRedirectInfo(ctx, clientID)
	return err == nil
}

// optionalUUID stores uuid.Nil as SQL NULL.
func optionalUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil}
}

// HasConsent reports whether the user has already granted the client every
// requested scope (so the consent screen can be skipped).
func (s *Service) HasConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) (bool, error) {
	member, err := s.activeClientTenantMember(ctx, userID, clientID)
	if err != nil {
		return false, err
	}
	if !member {
		return false, errs.ErrOIDCUserTenantMismatch
	}
	granted, err := s.q.GetConsent(ctx, dbgen.GetConsentParams{UserID: userID, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, sc := range scopes {
		if !contains(granted, sc) {
			return false, nil
		}
	}
	return true, nil
}

// GrantConsent records the user's approval of a client for the given scopes,
// replacing any prior grant for that (user, client) pair.
func (s *Service) GrantConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	member, err := s.activeClientTenantMember(ctx, userID, clientID)
	if err != nil {
		return err
	}
	if !member {
		return errs.ErrOIDCUserTenantMismatch
	}
	return s.q.UpsertConsent(ctx, dbgen.UpsertConsentParams{UserID: userID, ClientID: clientID, Scopes: scopes})
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	// IssuedTokenType is set for RFC 8693 token-exchange responses.
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// RFC 8693 token-exchange identifiers.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// authedClient is the client a request identified itself as. For a public
// client that identity is only claimed: its client_id is in every sign-in link
// and it has no secret, so an endpoint that needs proof calls
// requireConfidential.
type authedClient struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	ClientID   string
	Type       string
	GrantTypes []string
}

// authenticateClient identifies the calling client: a confidential client must
// present its secret, a public one presents none. A wrong secret is audited
// against the client's tenant. Unknown client ids are refused without an audit
// row, so an unauthenticated caller can't fill the audit trail.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (authedClient, error) {
	row, err := s.q.GetClientForAuth(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authedClient{}, errs.ErrOIDCClientAuthFailed
	}
	if err != nil {
		return authedClient{}, err
	}
	c := authedClient{ID: row.ID, TenantID: row.TenantID, ClientID: clientID, Type: row.Type, GrantTypes: row.GrantTypes}
	if row.Type == "confidential" {
		// A locked-out application is refused before its secret is compared
		// (a memory-hard hash per guess), with the same answer as a wrong one.
		locked, err := s.clientLocked(ctx, row.ID)
		if err != nil {
			return authedClient{}, err
		}
		if locked {
			return authedClient{}, errs.ErrOIDCClientAuthFailed
		}
		if row.ClientSecretHash == nil || !password.Verify(*row.ClientSecretHash, clientSecret) {
			s.clientAuthFailed(ctx, c)
			return authedClient{}, errs.ErrOIDCClientAuthFailed
		}
		if err := s.q.ClearClientAuthFailures(ctx, row.ID); err != nil {
			return authedClient{}, err
		}
	}
	return c, nil
}

// requireConfidential refuses a public client at an endpoint that relies on
// client authentication (introspection, token exchange, backchannel sign-in):
// for a public client, presenting its client_id proves nothing.
func (s *Service) requireConfidential(ctx context.Context, c authedClient) error {
	if c.Type == "confidential" {
		return nil
	}
	s.auditClientAuthFailure(ctx, c, "public_client")
	return errs.ErrOIDCClientAuthFailed
}

// auditClientAuthFailure records a refused client authentication. Best-effort:
// the refusal stands whether or not the row is written.
func (s *Service) auditClientAuthFailure(ctx context.Context, c authedClient, reason string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	tenantID, id := c.TenantID, c.ID
	if audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "client", Action: "oidc.client_auth_failed",
		ResourceType: "oidc_client", ResourceID: &id, IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{"client_id": c.ClientID, "reason": reason},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

// TokenExchange implements RFC 8693 downscoping: a confidential client with the
// token_exchange grant swaps a valid access token for a new one with a subset of
// its scopes. It never adds scopes or changes the subject or tenant.
func (s *Service) TokenExchange(ctx context.Context, clientID, clientSecret, subjectToken, subjectTokenType, requestedTokenType, scope, actorToken, actorTokenType, resource string) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return nil, err
	}
	if err := s.checkResource(ctx, client.TenantID, resource); err != nil {
		return nil, err
	}
	if !containsAny(client.GrantTypes, "token_exchange", grantTypeTokenExchange) {
		return nil, errs.ErrOIDCGrantTypeNotAllowed
	}
	if subjectToken == "" {
		return nil, errs.ErrOIDCSubjectTokenRequired
	}
	if subjectTokenType != "" && subjectTokenType != tokenTypeAccessToken {
		return nil, errs.ErrOIDCSubjectTokenTypeUnsupported
	}
	if requestedTokenType != "" && requestedTokenType != tokenTypeAccessToken {
		return nil, errs.ErrOIDCRequestedTokenTypeUnsupported
	}
	// Whatever its audience; who may exchange it is decided below.
	claims, err := s.issuer.VerifyAccessAnyAudience(subjectToken)
	if err != nil {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	// The subject token must belong to the calling client's tenant; otherwise any
	// client could keep renewing an access token stolen from another tenant.
	caller, err := s.q.GetClientName(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != caller.TenantID {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, errs.ErrOIDCSubjectTokenNoSubject
	}
	// The caller must be entitled to the subject's token: issued to it, issued
	// for a resource it serves, or the person delegated to it (consented).
	// Otherwise an application allowed to exchange could mint tokens in the
	// name of anyone whose token passes through it, an administrator's too.
	entitled, err := s.mayExchange(ctx, caller.TenantID, clientID, userID, claims)
	if err != nil {
		return nil, err
	}
	if !entitled {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	// A suspended or deleted person, or a closed organisation, gets nothing.
	live, err := s.activeTenantPrincipal(ctx, userID, claims.TenantID)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errs.ErrAuthAccountSuspended
	}
	// A chain of exchanges is bounded.
	if claims.ExchangeDepth >= s.exchangeMaxDepth {
		return nil, errs.ErrOIDCExchangeDepthExceeded
	}
	// Downscope: the result is at most the subject's scopes (never escalate).
	granted, ok := downscope(strings.Fields(claims.Scope), scope)
	if !ok {
		return nil, errs.ErrOIDCScopeExceedsSubject
	}
	// Delegation (RFC 8693): an actor_token names the party acting on the
	// subject's behalf (e.g. an AI agent exercising a user's authority). The
	// issued token records it in an `act` claim for downstream authz + audit.
	var actorSubject string
	if actorToken != "" {
		if actorTokenType != "" && actorTokenType != tokenTypeAccessToken {
			return nil, errs.ErrOIDCActorTokenTypeUnsupported
		}
		actorClaims, aerr := s.issuer.VerifyAccess(actorToken)
		if aerr != nil {
			return nil, errs.ErrOIDCActorTokenInvalid
		}
		// The delegating actor must also be inside the caller's tenant, or the
		// `act` claim could name a principal from another organisation.
		if actorClaims.TenantID != caller.TenantID {
			return nil, errs.ErrOIDCActorTokenInvalid
		}
		actorSubject = actorClaims.Subject
	}
	// A session of its own, linked to the one it came from in the audit
	// record, so the chain doesn't read as one sign-in.
	sid := uuid.New()
	scopeStr := strings.Join(granted, " ")
	// Never outlive the subject token: exchange can't extend a credential.
	var notAfter time.Time
	if claims.ExpiresAt != nil {
		notAfter = claims.ExpiresAt.Time
	}
	var (
		access string
		exp    time.Time
	)
	// Issued to the requesting client, which it names: an exchange cannot turn
	// an application token into one the management API accepts.
	access, exp, err = s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, TenantID: claims.TenantID, SessionID: sid, Scopes: scopeStr,
		ActorSubject: actorSubject, Resource: resource, ClientID: clientID,
		NotAfter: notAfter, ExchangeDepth: claims.ExchangeDepth + 1,
	})
	if err != nil {
		return nil, err
	}
	if err := s.auditExchange(ctx, claims, clientID, userID, sid, actorSubject, scopeStr, resource, exp); err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken:     access,
		TokenType:       "Bearer",
		ExpiresIn:       int(time.Until(exp).Seconds()),
		Scope:           scopeStr,
		IssuedTokenType: tokenTypeAccessToken,
	}, nil
}

// downscope returns the scopes to grant for a token-exchange: the requested
// scopes if every one is held by the subject (never escalate), or the subject's
// own scopes when no scope is requested. ok=false means the request asked for a
// scope the subject token doesn't carry.
func downscope(subjectScopes []string, requestedScope string) (granted []string, ok bool) {
	if strings.TrimSpace(requestedScope) == "" {
		return subjectScopes, true
	}
	requested := strings.Fields(requestedScope)
	for _, r := range requested {
		if !contains(subjectScopes, r) {
			return nil, false
		}
	}
	return requested, true
}

func containsAny(set []string, vs ...string) bool {
	for _, v := range vs {
		if contains(set, v) {
			return true
		}
	}
	return false
}

// ExchangeCode swaps an authorization_code for tokens.
func (s *Service) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier, resource string) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	clientInfo, err := s.q.GetClientForAuth(ctx, clientID)
	if err != nil {
		return nil, err
	}
	hash := codes.Hash(code)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	ac, err := q.ConsumeAuthorizationCode(ctx, dbgen.ConsumeAuthorizationCodeParams{CodeHash: hash, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCAuthCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	userID := ac.UserID
	tenantID := ac.TenantID
	scopes := ac.Scopes
	nonce := ac.Nonce
	challenge := ac.CodeChallenge
	method := ac.CodeChallengeMethod
	if ac.UsedAt.Valid {
		// A code presented twice was seen by someone else: end what its first
		// redemption issued (RFC 6749 §4.1.2), then refuse.
		if err := s.revokeGrantFromCode(ctx, tx, clientID, hash, userID, tenantID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrOIDCAuthCodeUsed
	}
	if time.Now().After(ac.ExpiresAt) {
		return nil, errs.ErrOIDCAuthCodeExpired
	}
	if ac.RedirectUri != redirectURI {
		return nil, errs.ErrOIDCRedirectURIMismatch
	}
	// The token is for the resource the authorization named; a token request
	// may repeat it but not name another.
	if ac.Resource != nil && *ac.Resource != "" {
		if resource != "" && resource != *ac.Resource {
			return nil, oauthErr("invalid_target", "resource differs from the one the authorization was for")
		}
		resource = *ac.Resource
	}
	if err := s.checkResource(ctx, tenantID, resource); err != nil {
		return nil, err
	}
	// A code issued with no challenge redeems only while its confidential
	// application's exemption is still in force.
	if (challenge == nil || *challenge == "") && (clientInfo.Type != "confidential" || !clientInfo.PkceExempt) {
		return nil, errs.ErrOIDCCodeChallengeRequired
	}
	if challenge != nil && *challenge != "" {
		if codeVerifier == "" {
			return nil, errs.ErrOIDCCodeVerifierRequired
		}
		if !validPKCEValue(codeVerifier, 43, 128) {
			return nil, errs.ErrOIDCCodeVerifierInvalid
		}
		// We support S256 only (the recommended PKCE method).
		if method == nil || *method != "S256" {
			return nil, errs.ErrOIDCCodeChallengeMethodUnsupported
		}
		computed := codes.Hash(codeVerifier)
		if subtle.ConstantTimeCompare([]byte(computed), []byte(*challenge)) != 1 {
			return nil, errs.ErrOIDCCodeVerifierInvalid
		}
	}
	// A code issued before the account was suspended or deleted is spent, not
	// redeemed.
	active, err := accountActive(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	if err := q.MarkAuthorizationCodeUsed(ctx, hash); err != nil {
		return nil, err
	}
	if !active {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrAuthAccountSuspended
	}
	// The grant is written while the code is still locked, so a sign-out of
	// the hosted-login session the code came from either spends the code first
	// (and this redemption fails) or waits and then ends the grant.
	refresh := ""
	if contains(client.GrantTypes, "refresh_token") {
		refresh, err = s.issueRefreshToken(ctx, q, clientID, userID, tenantID, scopes, resource, ac.LoginSessionID, hash)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	sessionID := uuid.New()
	// RFC 8707: bind the token's audience to the requested resource (if any).
	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, TenantID: tenantID, SessionID: sessionID, Scopes: strings.Join(scopes, " "), Resource: resource, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(ctx, idToken{
			UserID: userID, TenantID: tenantID, Audience: clientID, Nonce: derefStr(nonce), Scopes: scopes,
			AuthTime: timeOrZero(ac.AuthTime), SessionID: uuidOrNil(ac.LoginSessionID),
		})
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// issueRefreshToken stores a refresh token for the client and user and returns
// it. resource is the RFC 8707 resource bound to the access token ("" for none),
// loginSessionID the hosted-login session (NULL for none) and codeHash the
// redeemed code ("" for none). q lets it run in the caller's transaction.
func (s *Service) issueRefreshToken(ctx context.Context, q *dbgen.Queries, clientID string, userID, tenantID uuid.UUID, scopes []string, resource string, loginSessionID pgtype.UUID, codeHash string) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	var res *string
	if resource != "" {
		res = &resource
	}
	exp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	if err := q.InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		ID:        uuid.New(),
		TokenHash: hash, ClientID: clientID, UserID: userID, TenantID: tenantID,
		Scopes: scopes, ExpiresAt: exp, Resource: res, LoginSessionID: loginSessionID,
		DefaultMaxAgeSeconds: s.grantMaxAge.Seconds(), AuthorizationCodeHash: optionalString(codeHash),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// RefreshToken handles the refresh_token grant: it rotates the token and
// reissues tokens for the original grant. Replaying a used token revokes every
// live token for the client and user. A non-empty resource (RFC 8707) replaces
// the bound resource; otherwise the bound one carries forward.
func (s *Service) RefreshToken(ctx context.Context, clientID, clientSecret, rawRefresh, resource string) (*TokenResponse, error) {
	if _, err := s.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	if rawRefresh == "" {
		return nil, errs.ErrOIDCRefreshTokenRequired
	}
	hash := tokens.HashRefresh(rawRefresh)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	rt, err := q.LockRefreshToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCRefreshTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	// A refresh token may only be redeemed by the client it was issued to.
	if rt.ClientID != clientID {
		return nil, errs.ErrOIDCRefreshTokenClientMismatch
	}
	if rt.RevokedAt.Valid {
		return nil, errs.ErrOIDCRefreshTokenRevoked
	}
	// A suspended or deleted account renews nothing, and the application's
	// grants for it end, so reactivating the account doesn't revive them.
	active, err := accountActive(ctx, q, rt.UserID)
	if err != nil {
		return nil, err
	}
	if !active {
		if err := q.RevokeRefreshTokenChain(ctx, dbgen.RevokeRefreshTokenChainParams{ClientID: clientID, UserID: rt.UserID}); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrAuthAccountSuspended
	}
	if rt.UsedAt.Valid {
		// Reuse — assume theft: revoke every live token for this (client, user) and audit it.
		if err := s.handleRefreshReuse(ctx, tx, clientID, rt.UserID, rt.TenantID, rt.ID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrOIDCRefreshTokenReuse
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, errs.ErrOIDCRefreshTokenExpired
	}
	if resource == "" && rt.Resource != nil {
		resource = *rt.Resource
	} else if err := s.checkResource(ctx, rt.TenantID, resource); err != nil {
		return nil, err
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	var newRes *string
	if resource != "" {
		newRes = &resource
	}
	newExp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	newID, err := q.InsertRotatedRefreshToken(ctx, dbgen.InsertRotatedRefreshTokenParams{
		TokenHash: newHash, ClientID: clientID, UserID: rt.UserID, TenantID: rt.TenantID,
		Scopes: rt.Scopes, ExpiresAt: newExp, Resource: newRes, LoginSessionID: rt.LoginSessionID,
		GrantExpiresAt: rt.GrantExpiresAt, AuthorizationCodeHash: rt.AuthorizationCodeHash,
		GrantID: rt.GrantID,
	})
	if err != nil {
		return nil, err
	}
	if err := q.MarkRefreshTokenUsed(ctx, dbgen.MarkRefreshTokenUsedParams{
		NewID: pgtype.UUID{Bytes: newID, Valid: true},
		ID:    rt.ID,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	userID := rt.UserID
	tenantID := rt.TenantID
	scopes := rt.Scopes

	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, TenantID: tenantID, SessionID: uuid.New(), Scopes: strings.Join(scopes, " "), Resource: resource, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(ctx, idToken{UserID: userID, TenantID: tenantID, Audience: clientID, Scopes: scopes})
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: newRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// handleRefreshReuse revokes every live refresh token for a (client, user) on replay and audits it.
// accountActive reports whether a user may still be issued tokens by any
// application grant: not suspended and not deleted, the rule the first-party
// refresh applies. A user who no longer exists is not active.
func accountActive(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) (bool, error) {
	row, err := q.GetAccountStanding(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !row.Deleted && row.Status != "suspended", nil
}

// mayExchange reports whether clientID may exchange a subject token of its
// tenant: the token was issued to it, or for a registered resource it serves,
// or the person has consented to it (a delegation it holds).
func (s *Service) mayExchange(ctx context.Context, tenantID uuid.UUID, clientID string, userID uuid.UUID, claims *tokens.Claims) (bool, error) {
	if ok, err := s.mayIntrospect(ctx, tenantID, clientID, claims); err != nil || ok {
		return ok, err
	}
	_, err := s.q.GetConsent(ctx, dbgen.GetConsentParams{UserID: userID, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// auditExchange records a token exchange: caller, subject, actor, scopes,
// resource, and the session the subject token came from.
func (s *Service) auditExchange(ctx context.Context, subject *tokens.Claims, clientID string, userID, sid uuid.UUID, actor, scopes, resource string, exp time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tenantID := subject.TenantID
	meta := map[string]any{
		"client_id": clientID, "scope": scopes, "resource": resource, "actor": actor,
		"subject_client_id": subject.ClientID, "exchange_depth": subject.ExchangeDepth + 1,
		"session_id": sid, "expires_at": exp,
	}
	if subject.SessionID != uuid.Nil {
		meta["from_session_id"] = subject.SessionID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "client",
		Action: "oidc.token_exchanged", ResourceType: "oidc_client", IP: httpx.ClientIPFromContext(ctx),
		Metadata: meta,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// mayIntrospect reports whether clientID may see an access token of its
// tenant: it is the application the token was issued to (client_id claim), or
// it serves one of the registered resources the token was issued for.
func (s *Service) mayIntrospect(ctx context.Context, tenantID uuid.UUID, clientID string, claims *tokens.Claims) (bool, error) {
	if claims.ClientID != "" && claims.ClientID == clientID {
		return true, nil
	}
	res := resourcesOf(claims.Audience, s.issuer.JWTAudience())
	if len(res) == 0 {
		return false, nil
	}
	return s.q.ResourceServedBy(ctx, dbgen.ResourceServedByParams{TenantID: tenantID, ClientID: &clientID, Identifiers: res})
}

// auditIntrospectionRefused records an application asking about a token it
// doesn't own (owner "" for a token issued to no application).
func (s *Service) auditIntrospectionRefused(ctx context.Context, tenantID uuid.UUID, caller, owner string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "client", Action: "oidc.introspection_refused",
		ResourceType: "oidc_client", IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{"client_id": caller, "token_client_id": owner, "outcome": "inactive"},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

// resourcesOf is an audience without the platform's own entry: the resources
// a token was issued for.
func resourcesOf(aud []string, platform string) []string {
	var out []string
	for _, a := range aud {
		if a != platform {
			out = append(out, a)
		}
	}
	return out
}

// audienceClaim renders an audience as JWT does: one value as a string,
// several as a list.
func audienceClaim(aud []string) any {
	if len(aud) == 1 {
		return aud[0]
	}
	return aud
}

// revokeGrantFromCode ends the grant redeemed from the authorization code
// with this hash, after the code was presented again, and records it.
func (s *Service) revokeGrantFromCode(ctx context.Context, tx pgx.Tx, clientID, codeHash string, userID, tenantID uuid.UUID) error {
	n, err := s.q.WithTx(tx).RevokeGrantFromCode(ctx, dbgen.RevokeGrantFromCodeParams{
		ClientID: clientID, AuthorizationCodeHash: &codeHash,
	})
	if err != nil {
		return err
	}
	tid, uid := tenantID, userID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "oidc.authorization_code_reused",
		ResourceType: "oidc_client",
		Metadata: map[string]any{
			"client_id":      clientID,
			"grants_revoked": n,
			"reason":         "authorization_code_reuse",
		},
	})
}

// optionalString is s for a nullable column, nil for "".
func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx, clientID string, userID, tenantID, tokenID uuid.UUID) error {
	q := s.q.WithTx(tx)
	if err := q.RevokeRefreshTokenChain(ctx, dbgen.RevokeRefreshTokenChainParams{
		ClientID: clientID, UserID: userID,
	}); err != nil {
		return err
	}
	tid, uid, rid := tenantID, userID, tokenID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "oidc.refresh_reuse_detected",
		ResourceType: "oidc_refresh_token",
		ResourceID:   &rid,
		Metadata: map[string]any{
			"client_id":        clientID,
			"refresh_token_id": tokenID,
			"reason":           "refresh_token_reuse",
		},
	})
}

// idToken is what an ID token is minted from.
type idToken struct {
	UserID, TenantID uuid.UUID
	// Audience is the client the token is for; Nonce the one the
	// authorization request sent ("" for none).
	Audience, Nonce string
	// Scopes decide which standard claims it carries (see userClaims).
	Scopes []string
	// AuthTime is when the person signed in (zero: unknown), reported as
	// auth_time; SessionID is the hosted-login session (uuid.Nil: none),
	// reported as sid so a sign-out notice can name it.
	AuthTime  time.Time
	SessionID uuid.UUID
}

func (s *Service) signIDToken(ctx context.Context, in idToken) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(s.issuer.AccessTTL())
	claims := jwt.MapClaims{
		"iss":       s.issuer.JWTIssuer(),
		"sub":       in.UserID.String(),
		"aud":       in.Audience,
		"exp":       exp.Unix(),
		"iat":       now.Unix(),
		"tenant_id": in.TenantID.String(),
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}
	if !in.AuthTime.IsZero() {
		claims["auth_time"] = in.AuthTime.Unix()
	}
	if in.SessionID != uuid.Nil {
		claims["sid"] = in.SessionID.String()
	}
	user, err := s.userClaims(ctx, in.UserID, in.Scopes)
	if err != nil {
		return "", err
	}
	for k, v := range user {
		claims[k] = v
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

// SessionManager resolves and ends the hosted-login SSO cookie. Satisfied by
// *auth.Service; an interface keeps the dependency one-way.
type SessionManager interface {
	ResolveLoginSession(ctx context.Context, raw string) (uuid.UUID, error)
	ResolveLoginSessionWithID(ctx context.Context, raw string) (sessionID, userID uuid.UUID, err error)
	ResolveLoginSessionAt(ctx context.Context, raw string) (sessionID, userID uuid.UUID, signedInAt time.Time, err error)
	EndLoginSession(ctx context.Context, in auth.EndLoginSessionInput) (auth.LoginSessionEnded, error)
	// LoginSessionFactorShortfall says what stops a code or token being
	// issued for tenantID through the session: nil, or ErrStepUpRequired /
	// ErrMFAEnrollmentRequired while the organisation requires a second
	// factor its sign-in didn't meet.
	LoginSessionFactorShortfall(ctx context.Context, loginSessionID, userID, tenantID uuid.UUID) error
}

// ProviderLister lists a tenant's enabled social providers, so the hosted login
// app can render the right social buttons. Satisfied by *social.Service.
type ProviderLister interface {
	EnabledProviderNames(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// RegistrationChecker reports whether a tenant permits hosted self-registration,
// so the login-context tells the hosted app whether to show a signup link.
// Satisfied by *authpolicy.Service (optional).
type RegistrationChecker interface {
	SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// SignInMethodsChecker reports which sign-in methods a tenant allows, so the
// login-context tells the hosted login which to offer. Satisfied by
// *authpolicy.Service (optional).
type SignInMethodsChecker interface {
	AllowedSignInMethods(ctx context.Context, tenantID uuid.UUID) (password, passkey, magicLink bool, err error)
}

// DeviceTrustChecker reports whether a tenant has opted into adaptive MFA, so
// the login-context tells the hosted app whether to offer "remember this
// device" on the MFA step. Satisfied by *authpolicy.Service (optional).
type DeviceTrustChecker interface {
	RememberDeviceEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error)
}

// BrandingLister returns a tenant's hosted-login branding (logo + brand colors)
// so the login page can render the tenant's brand on first paint. Returns empty
// strings when unset. Satisfied by *branding.Repository (optional).
type BrandingLister interface {
	LoginBranding(ctx context.Context, tenantID uuid.UUID) (logoURL, primaryColor, secondaryColor, backgroundColor string)
}

type Handler struct {
	Service *Service
	// Sessions resolves the hosted-login SSO cookie for the authorize/consent
	// flow. LoginBaseURL is the origin of the hosted login app (qeetid-login)
	// the browser is redirected to for login/consent. Providers lists a tenant's
	// social providers for the login-context endpoint (optional).
	Sessions     SessionManager
	Providers    ProviderLister
	Registration RegistrationChecker
	DeviceTrust  DeviceTrustChecker
	Methods      SignInMethodsChecker
	Branding     BrandingLister
	LoginBaseURL string
	// CookieSecure marks the hosted-login SSO cookie Secure (HTTPS-only) when
	// clearing it on logout; set from SERVICE_ENV != "dev".
	CookieSecure bool
}

// Mount registers the authenticated admin/RP endpoints (require a user JWT or
// API key): client registration, userinfo (bearer access token), and grant
// administration.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/oidc/clients", h.registerClient)
	r.Get("/oauth/userinfo", h.userinfo)
	r.Post("/oauth/userinfo", h.userinfo) // OIDC Core §5.3.1 allows both
	r.Get("/oauth/bc-authorize/pending", h.pendingBackchannel)
	r.Post("/oauth/bc-authorize/decision", h.backchannelDecision)
	r.Get("/tenants/{tenantID}/oauth/grants", h.listGrants)
	r.Delete("/tenants/{tenantID}/oauth/grants/{id}", h.revokeGrant)

	// Tenant-scoped OIDC client management (admin UI). Reads/writes are confined
	// to the path tenant; create + mutate + rotate are audited.
	r.Post("/tenants/{tenantID}/oidc/clients", h.createTenantClient)
	r.Get("/tenants/{tenantID}/oidc/clients", h.listClients)
	r.Get("/tenants/{tenantID}/oidc/clients/{id}", h.getClient)
	r.Patch("/tenants/{tenantID}/oidc/clients/{id}", h.patchClient)
	r.Get("/tenants/{tenantID}/oidc/clients/{id}/auth-failures", h.clientAuthFailures)
	r.Get("/tenants/{tenantID}/oidc/resources", h.listResources)
	r.Post("/tenants/{tenantID}/oidc/resources", h.createResource)
	r.Delete("/tenants/{tenantID}/oidc/resources/{id}", h.deleteResource)
	r.Delete("/tenants/{tenantID}/oidc/clients/{id}", h.deleteClient)
	r.Post("/tenants/{tenantID}/oidc/clients/{id}/rotate-secret", h.rotateClientSecret)
	r.Get("/tenants/{tenantID}/oidc/clients/shadow-ai", h.shadowAI)
	r.Post("/tenants/{tenantID}/oidc/clients/{id}/review", h.reviewShadowAI)

	// The admin UI's list page wires Delete to the non-tenant-scoped
	// /v1/oidc/clients/{id}; the create sheet posts to /v1/oidc/clients (handled
	// by registerClient above). Tenant-scope this delete via the caller's JWT
	// tenant so it can never reach across tenants.
	r.Delete("/oidc/clients/{id}", h.deleteClientByScope)

	// Admin device-authorization visibility (RFC 8628 rows), tenant-scoped.
	r.Get("/tenants/{tenantID}/oauth/devices", h.listDevices)
	r.Delete("/tenants/{tenantID}/oauth/devices/{id}", h.revokeDevice)

	// Signing-key management (global/issuer-level, not tenant-scoped).
	r.Get("/oidc/signing-keys", h.signingKeys)
}

// MountBrowser registers the browser/RP-facing OAuth endpoints that authenticate
// via the SSO cookie or client credentials (not a user JWT), so they live in
// the public group. token-code is client-credential M2M and is CSRF-exempt in
// the router; authorize (GET) and decision (cookie POST) are not.
func (h *Handler) MountBrowser(r chi.Router) {
	r.Get("/oauth/authorize", h.authorize)
	r.Post("/oauth/authorize/decision", h.decision)
	r.Get("/oauth/authorize/request", h.consentRequest)
	r.Post("/oauth/token-code", h.tokenCode)
	r.Get("/oauth/login-context", h.loginContext)
	r.Get("/oauth/logout", h.endSession)  // RP-Initiated Logout
	r.Post("/oauth/logout", h.endSession) // (some RPs POST)
	r.Get("/oauth/logout/continue", h.endSessionContinue)
	// Device Authorization Grant (RFC 8628). device_authorization is
	// client-authenticated M2M (CSRF-exempt in the router, like token-code);
	// the device context + decision endpoints are SSO-cookie gated like
	// authorize/decision (the hosted /device page posts the user's choice).
	r.Post("/oauth/device_authorization", h.deviceAuthorization)
	r.Get("/oauth/device", h.deviceContext)
	r.Post("/oauth/device/decision", h.deviceDecision)
	// OpenID CIBA (poll mode). bc-authorize is client-credential M2M like
	// device_authorization above (CSRF-exempt in the router); the
	// pending/decision endpoints are bearer-JWT authenticated and live in
	// Mount, not here.
	r.Post("/oauth/bc-authorize", h.backchannelAuthorize)
}

// loginContext gives the hosted login app what it needs to render itself for a
// given client_id: the client's display name, its tenant, and the tenant's
// enabled social providers.
func (h *Handler) loginContext(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	name, tenantID, err := h.Service.ClientName(r.Context(), clientID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	providers := []string{}
	if h.Providers != nil {
		if p, perr := h.Providers.EnabledProviderNames(r.Context(), tenantID); perr == nil {
			providers = p
		}
	}
	selfRegistration := false
	if h.Registration != nil {
		if enabled, rerr := h.Registration.SelfRegistrationEnabled(r.Context(), tenantID); rerr == nil {
			selfRegistration = enabled
		}
	}
	rememberDevice := false
	if h.DeviceTrust != nil {
		if enabled, derr := h.DeviceTrust.RememberDeviceEnabled(r.Context(), tenantID); derr == nil {
			rememberDevice = enabled
		}
	}
	// Which sign-in methods the tenant allows, so the hosted login offers only
	// those (each is also refused where the credential is accepted). All on when
	// no checker is wired or it cannot be read.
	methods := map[string]bool{"password": true, "passkey": true, "magic_link": true}
	if h.Methods != nil {
		if password, passkey, magic, merr := h.Methods.AllowedSignInMethods(r.Context(), tenantID); merr == nil {
			methods = map[string]bool{"password": password, "passkey": passkey, "magic_link": magic}
		}
	}
	// Per-tenant branding (logo + brand colors) so the hosted login can render
	// the tenant's brand on first paint. Omitted entirely when nothing is set.
	var brand map[string]any
	if h.Branding != nil {
		if logo, primary, secondary, background := h.Branding.LoginBranding(r.Context(), tenantID); logo != "" || primary != "" || secondary != "" || background != "" {
			brand = map[string]any{}
			if logo != "" {
				brand["logo_url"] = logo
			}
			if primary != "" {
				brand["primary_color"] = primary
			}
			if secondary != "" {
				brand["secondary_color"] = secondary
			}
			if background != "" {
				brand["background_color"] = background
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_name":               name,
		"tenant_id":                 tenantID,
		"providers":                 providers,
		"self_registration_enabled": selfRegistration,
		"remember_device_enabled":   rememberDevice,
		"sign_in_methods":           methods,
		"branding":                  brand,
	})
}

func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/.well-known/openid-configuration", h.discovery)
	r.Get("/.well-known/oauth-authorization-server", h.authorizationServerMetadata) // RFC 8414
	r.Get("/.well-known/jwks.json", h.jwks)
	r.Get("/.well-known/oauth-protected-resource", h.protectedResourceMetadata) // RFC 9728
	// Client-authenticated, machine-to-machine; CSRF-exempt in the router.
	r.Post("/oauth/revoke", h.revoke)         // RFC 7009
	r.Post("/oauth/introspect", h.introspect) // RFC 7662
}

func (h *Handler) registerClient(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateClientInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.TenantID = tenantID
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
	auditTenantID := c.TenantID
	resourceID := c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &auditTenantID,
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

// authorize handles GET /oauth/authorize. It identifies the user by the SSO
// cookie and redirects to the hosted login, to the consent screen, or back to
// the client's redirect_uri with a code.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	scopes := strings.Fields(q.Get("scope"))

	// Nothing about this request is trusted until its redirect_uri is one the
	// client registered: until then the error is shown here, never sent there.
	if !h.Service.RegisteredRedirect(r.Context(), clientID, redirect) {
		httpx.WriteError(w, r, errs.ErrOIDCRedirectURINotRegistered)
		return
	}
	if err := checkAuthorizeRequest(q); err != nil {
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	}
	silent := slices.Contains(prompts(q), "none")

	loginSessionID, userID, signedInAt, ok := h.loginSessionAt(r)
	now := time.Now()
	switch {
	case !ok && silent:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("login_required", "no active sign-in"))
		return
	case !ok:
		http.Redirect(w, r, h.LoginBaseURL+"/login?return_to="+url.QueryEscape(currentURL(r)), http.StatusFound)
		return
	case signInRequired(q, signedInAt, now) && silent:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("login_required", "a fresh sign-in is required"))
		return
	case signInRequired(q, signedInAt, now):
		// prompt=login or max_age: sign in again, then come back to this request.
		http.Redirect(w, r, h.LoginBaseURL+"/login?prompt=login&return_to="+url.QueryEscape(reauthReturnTo(r, now)), http.StatusFound)
		return
	}

	// The application's organisation may require a second factor this sign-in
	// didn't meet. The hosted sign-in asks for the requirement of the
	// application it serves, so the browser signs in again for this request,
	// once; a fresh sign-in that still hasn't met one is refused.
	switch err := h.factorShortfall(r.Context(), loginSessionID, userID, clientID); {
	case err == nil:
	case !isFactorShortfall(err):
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	case silent:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("interaction_required", "the organisation requires a second factor"))
		return
	case !signedInForRequest(q, signedInAt):
		http.Redirect(w, r, h.LoginBaseURL+"/login?prompt=login&return_to="+url.QueryEscape(reauthReturnTo(r, now)), http.StatusFound)
		return
	default:
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("access_denied", "the organisation requires a second factor"))
		return
	}

	has, err := h.Service.HasConsent(r.Context(), userID, clientID, scopes)
	if err != nil {
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	}
	if !has && silent {
		h.authorizeError(w, r, clientID, redirect, state, oauthErr("consent_required", "consent is required"))
		return
	}
	if !has || slices.Contains(prompts(q), "consent") {
		// Hand off to the hosted consent screen with only the id of the request
		// stored here; the decision acts on the stored values, not on anything
		// the browser sends back.
		id, err := h.Service.StartConsentRequest(r.Context(), loginSessionID, userID, ConsentRequest{
			ClientID: clientID, RedirectURI: redirect, Scopes: scopes, State: state,
			Nonce: q.Get("nonce"), CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
			Resource: q.Get("resource"),
		})
		if err != nil {
			h.authorizeError(w, r, clientID, redirect, state, err)
			return
		}
		http.Redirect(w, r, h.LoginBaseURL+"/consent?request_id="+url.QueryEscape(id.String()), http.StatusFound)
		return
	}

	code, _, err := h.Service.AuthorizeInLoginSession(r.Context(), AuthorizeInput{
		LoginSessionID: loginSessionID, UserID: userID, ClientID: clientID, RedirectURI: redirect, Scopes: scopes,
		Nonce: q.Get("nonce"), CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
		IP: httpx.ClientIP(r), Resource: q.Get("resource"), AuthTime: signedInAt,
	})
	if err != nil {
		h.authorizeError(w, r, clientID, redirect, state, err)
		return
	}
	// RFC 9207: identify the issuer in the authorization response.
	http.Redirect(w, r, appendQuery(redirect, "code", code, "state", state, "iss", h.Service.issuer.JWTIssuer()), http.StatusFound)
}

// authorizeError reports a failure before a code was issued. Per RFC 6749
// §4.1.2.1 it redirects to the client's redirect_uri, but only when that URI is
// registered; otherwise it renders the error, so it is never an open redirect.
func (h *Handler) authorizeError(w http.ResponseWriter, r *http.Request, clientID, redirect, state string, err error) {
	if redirect == "" || !h.Service.RegisteredRedirect(r.Context(), clientID, redirect) {
		httpx.WriteError(w, r, err)
		return
	}
	oauthCode := "server_error"
	var oe *oauthError
	switch {
	case errors.As(err, &oe):
		oauthCode = oe.Code
	case errors.Is(err, errs.ErrOIDCUserTenantMismatch),
		errors.Is(err, errs.ErrAuthAddressNotAllowed):
		oauthCode = "access_denied"
	case errors.Is(err, errs.ErrOIDCScopeNotPermitted):
		oauthCode = "invalid_scope"
	case errors.Is(err, errs.ErrOIDCCodeChallengeRequired),
		errors.Is(err, errs.ErrOIDCCodeChallengeInvalid),
		errors.Is(err, errs.ErrOIDCCodeChallengeMethodUnsupported),
		errors.Is(err, errs.ErrOIDCNonceRequired),
		errors.Is(err, errs.ErrOIDCNonceInvalid):
		oauthCode = "invalid_request"
	case errors.Is(err, errs.ErrOIDCRedirectURIInvalid):
		// The URI validated as registered above, so this is some other
		// redirect-shaped rejection; do not bounce it back.
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, appendQuery(redirect,
		"error", oauthCode, "state", state, "iss", h.Service.issuer.JWTIssuer()), http.StatusFound)
}

type decisionInput struct {
	RequestID string `json:"request_id"`
	Approve   bool   `json:"approve"`
	// The request's own values, as an older consent screen echoed them. They
	// are optional and never used: one that is sent must match the stored
	// request, or the decision is refused.
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// matches reports whether every echoed value that was sent equals the stored
// request's.
func (in decisionInput) matches(req *ConsentRequest) bool {
	same := func(sent, stored string) bool { return sent == "" || sent == stored }
	return same(in.ClientID, req.ClientID) && same(in.RedirectURI, req.RedirectURI) &&
		same(strings.Join(strings.Fields(in.Scope), " "), strings.Join(req.Scopes, " ")) &&
		same(in.State, req.State) && same(in.Nonce, req.Nonce) &&
		same(in.CodeChallenge, req.CodeChallenge) && same(in.CodeChallengeMethod, req.CodeChallengeMethod)
}

// decision records the user's choice on the hosted consent screen and returns,
// as JSON, the URL to navigate to: a code on approval, or error=access_denied.
// The request's values come from storage, never from the browser.
func (h *Handler) decision(w http.ResponseWriter, r *http.Request) {
	loginSessionID, userID, ok := h.loginSession(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in decisionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(in.RequestID)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrOIDCConsentRequestInvalid)
		return
	}
	req, err := h.Service.TakeConsentRequest(r.Context(), id, loginSessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if req.UserID != userID || !in.matches(req) {
		httpx.WriteError(w, r, errs.ErrOIDCConsentRequestInvalid)
		return
	}
	// The client may have dropped the address since the request was stored.
	if !h.Service.RegisteredRedirect(r.Context(), req.ClientID, req.RedirectURI) {
		httpx.WriteError(w, r, errs.ErrOIDCRedirectURINotRegistered)
		return
	}
	if !in.Approve {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"redirect": appendQuery(req.RedirectURI, "error", "access_denied", "state", req.State, "iss", h.Service.issuer.JWTIssuer()),
		})
		return
	}
	if err := h.factorShortfall(r.Context(), loginSessionID, userID, req.ClientID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.GrantConsent(r.Context(), userID, req.ClientID, req.Scopes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	_, _, signedInAt, _ := h.loginSessionAt(r)
	code, _, err := h.Service.AuthorizeInLoginSession(r.Context(), AuthorizeInput{
		LoginSessionID: loginSessionID, UserID: userID, ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Scopes: req.Scopes, Nonce: req.Nonce, CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
		IP: httpx.ClientIP(r), Resource: req.Resource, AuthTime: signedInAt,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"redirect": appendQuery(req.RedirectURI, "code", code, "state", req.State, "iss", h.Service.issuer.JWTIssuer()),
	})
}

// consentRequest is what the hosted consent screen shows: the client and the
// scopes of the stored request, for the browser that started it.
func (h *Handler) consentRequest(w http.ResponseWriter, r *http.Request) {
	loginSessionID, _, ok := h.loginSession(r)
	if !ok {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := uuid.Parse(r.URL.Query().Get("request_id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrOIDCConsentRequestInvalid)
		return
	}
	req, err := h.Service.GetConsentRequest(r.Context(), id, loginSessionID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"request_id": req.ID,
		"client_id":  req.ClientID,
		"scope":      strings.Join(req.Scopes, " "),
	})
}

// endSession is the OIDC RP-Initiated Logout endpoint. It ends the browser's
// hosted SSO session and what it started, clears the cookie, and redirects to a
// registered post_logout_redirect_uri or shows the signed-out page. If sign-out
// fails, the error is shown and the cookie kept.
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	redirect := r.Form.Get("post_logout_redirect_uri")
	clientID := r.Form.Get("client_id")
	state := r.Form.Get("state")
	hint := r.Form.Get("id_token_hint")
	sessionID, userID, _, hasSession := h.loginSessionAt(r)

	switch {
	case hint != "":
		// The hint names whose sign-in this is: it must be this one.
		lh, err := h.Service.checkLogoutHint(hint, clientID, sessionID, userID)
		if err != nil {
			var oe *oauthError
			if errors.As(err, &oe) {
				writeOAuthError(w, oe)
				return
			}
			httpx.WriteError(w, r, err)
			return
		}
		if clientID == "" {
			clientID = lh.ClientID
		}
	case hasSession && !h.Service.confirmedFor(r.Form.Get("logout_confirmation"), sessionID):
		// No hint and no confirmation: a plain link or image must not sign
		// anyone out. The hosted login asks, then comes back with the ticket.
		ticket, err := h.Service.logoutConfirmation(sessionID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		q := url.Values{"logout_confirmation": {ticket}}
		for _, k := range []string{"client_id", "post_logout_redirect_uri", "state"} {
			if v := r.Form.Get(k); v != "" {
				q.Set(k, v)
			}
		}
		http.Redirect(w, r, h.LoginBaseURL+"/logout?"+q.Encode(), http.StatusFound)
		return
	}

	var frontchannel []string
	if c, err := r.Cookie(auth.LoginSessionCookie); err == nil {
		in := auth.EndLoginSessionInput{
			Cookie: c.Value, InitiatedBy: auth.SignOutByApplication,
			IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		}
		if clientID != "" && h.Service.RegisteredClient(r.Context(), clientID) {
			in.ClientID = clientID
		}
		ended, err := h.Sessions.EndLoginSession(r.Context(), in)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		frontchannel = ended.FrontChannelLogoutURIs
	}
	auth.ClearLoginSessionCookie(w, h.CookieSecure)

	next := ""
	if redirect != "" && clientID != "" {
		if ok, err := h.Service.ValidatePostLogoutRedirect(r.Context(), clientID, redirect); err == nil && ok {
			next = appendQuery(redirect, "state", state)
		}
	}
	if len(frontchannel) == 0 {
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, h.LoginBaseURL+"/logged-out", http.StatusFound)
		return
	}
	// The hosted signed-out page loads each application's front-channel page,
	// then continues to the validated address through a signed ticket (never
	// a plain URL it would have to trust).
	q := url.Values{"frontchannel_logout": frontchannel}
	if next != "" {
		ticket, err := h.Service.logoutContinuation(next)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		q.Set("continue", ticket)
	}
	http.Redirect(w, r, h.LoginBaseURL+"/logged-out?"+q.Encode(), http.StatusFound)
}

// endSessionContinue (GET /v1/oauth/logout/continue) sends the browser on to
// the post-logout address a sign-out validated, from the signed ticket the
// hosted signed-out page was given; anything else goes to the signed-out page.
func (h *Handler) endSessionContinue(w http.ResponseWriter, r *http.Request) {
	if next, ok := h.Service.continuationTarget(r.URL.Query().Get("ticket")); ok {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, h.LoginBaseURL+"/logged-out", http.StatusFound)
}

// factorShortfall is what stops a code or token being issued for clientID's
// organisation through the hosted-login session: nil, or the second factor
// the organisation still requires (see auth.Service.LoginSessionFactorShortfall).
func (h *Handler) factorShortfall(ctx context.Context, loginSessionID, userID uuid.UUID, clientID string) error {
	tenantID, err := h.Service.ClientTenant(ctx, clientID)
	if err != nil {
		return err
	}
	return h.Sessions.LoginSessionFactorShortfall(ctx, loginSessionID, userID, tenantID)
}

// isFactorShortfall reports whether err is a second factor still required.
func isFactorShortfall(err error) bool {
	return errors.Is(err, errs.ErrStepUpRequired) || errors.Is(err, errs.ErrMFAEnrollmentRequired)
}

// sessionUser resolves the hosted-login SSO cookie to a user id.
func (h *Handler) sessionUser(r *http.Request) (uuid.UUID, bool) {
	_, uid, ok := h.loginSession(r)
	return uid, ok
}

// loginSession resolves the hosted-login SSO cookie to the session's id and its
// user.
func (h *Handler) loginSession(r *http.Request) (sessionID, userID uuid.UUID, ok bool) {
	c, err := r.Cookie(auth.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	sessionID, userID, err = h.Sessions.ResolveLoginSessionWithID(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return sessionID, userID, true
}

// loginSessionAt is loginSession plus when the person signed in.
func (h *Handler) loginSessionAt(r *http.Request) (sessionID, userID uuid.UUID, signedInAt time.Time, ok bool) {
	c, err := r.Cookie(auth.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, false
	}
	sessionID, userID, signedInAt, err = h.Sessions.ResolveLoginSessionAt(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, false
	}
	return sessionID, userID, signedInAt, true
}

// externalScheme returns the request's public scheme: X-Forwarded-Proto from a
// TLS-terminating proxy, then the request's own TLS state, defaulting to https
// for non-localhost hosts.
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

// currentURL reconstructs the absolute URL of the current request (for the
// login redirect's return_to).
func currentURL(r *http.Request) string {
	return externalScheme(r) + "://" + r.Host + r.URL.RequestURI()
}

// appendQuery appends key/value pairs (skipping empty values) to a URL that may
// already carry a query string.
func appendQuery(base string, kv ...string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	out := base
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		out += sep + kv[i] + "=" + url.QueryEscape(kv[i+1])
		sep = "&"
	}
	return out
}

func (h *Handler) tokenCode(w http.ResponseWriter, r *http.Request) {
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// RFC 8707 §2 — validate the optional resource indicator if present.
	// The resource must be an absolute URI with a scheme; fragment components
	// are forbidden. An unrecognised or malformed value yields invalid_target.
	resource := r.Form.Get("resource")
	if resource != "" {
		u, parseErr := url.Parse(resource)
		if parseErr != nil || !u.IsAbs() || u.Fragment != "" {
			writeOAuthError(w, oauthErr("invalid_target", "resource must be an absolute URI without a fragment"))
			return
		}
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		clientID, clientSecret = u, p
	}
	var resp *TokenResponse
	var err error
	switch gt := r.Form.Get("grant_type"); {
	case resource != "" && (gt == "urn:ietf:params:oauth:grant-type:device_code" || gt == grantTypeCIBA):
		// Explicitly refused, never silently dropped: these flows bind no resource.
		writeOAuthError(w, oauthErr("invalid_target", "resource indicators aren't supported on the device and backchannel flows"))
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		resp, err = h.Service.ExchangeCode(r.Context(),
			clientID, clientSecret,
			r.Form.Get("code"), r.Form.Get("redirect_uri"), r.Form.Get("code_verifier"), resource)
	case "refresh_token":
		resp, err = h.Service.RefreshToken(r.Context(),
			clientID, clientSecret, r.Form.Get("refresh_token"), resource)
	case grantTypeTokenExchange:
		resp, err = h.Service.TokenExchange(r.Context(),
			clientID, clientSecret,
			r.Form.Get("subject_token"), r.Form.Get("subject_token_type"),
			r.Form.Get("requested_token_type"), r.Form.Get("scope"),
			r.Form.Get("actor_token"), r.Form.Get("actor_token_type"), resource)
	case "urn:ietf:params:oauth:grant-type:device_code":
		// RFC 8628 §3.4 polling: the device_code is the proof, so no client_secret is
		// needed. Errors use the RFC 6749 §5.2 shape.
		resp, err = h.Service.DeviceToken(r.Context(), clientID, r.Form.Get("device_code"), httpx.ClientIP(r))
		if err != nil {
			var oe *oauthError
			if errors.As(err, &oe) {
				writeOAuthError(w, oe)
				return
			}
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	case grantTypeCIBA:
		// OpenID CIBA §10 polling. Same error-rendering shape as device_code.
		resp, err = h.Service.BackchannelToken(r.Context(), clientID, r.Form.Get("auth_req_id"))
		if err != nil {
			var oe *oauthError
			if errors.As(err, &oe) {
				writeOAuthError(w, oe)
				return
			}
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	default:
		httpx.WriteError(w, r, errs.ErrOIDCGrantTypeUnsupported)
		return
	}
	if err != nil {
		var oe *oauthError
		if errors.As(err, &oe) {
			writeOAuthError(w, oe)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// clientCreds parses OAuth client credentials from the form body or HTTP Basic
// auth (the two RFC 6749 §2.3.1 mechanisms). Shared by revoke + introspect.
func (h *Handler) clientCreds(r *http.Request) (id, secret string, err error) {
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		return "", "", err
	}
	id = r.Form.Get("client_id")
	secret = r.Form.Get("client_secret")
	if u, p, has := r.BasicAuth(); has {
		id, secret = u, p
	}
	return id, secret, nil
}

// revoke is the RFC 7009 token-revocation endpoint. It always answers 200 with
// an empty body on success (including for unknown tokens).
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RevokeToken(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint")); err != nil {
		var oe *oauthError
		if errors.As(err, &oe) {
			writeOAuthError(w, oe)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// introspect is the RFC 7662 token-introspection endpoint.
func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp, err := h.Service.Introspect(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.serverMetadata(r))
}

// authorizationServerMetadata (GET /.well-known/oauth-authorization-server) is
// the RFC 8414 document an OAuth-only client, or a model-context-protocol
// client following the protected-resource document, configures itself from.
// The same document as the OpenID configuration, so the two can't disagree.
func (h *Handler) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.serverMetadata(r))
}

// serverMetadata is the authorization server's metadata, for the request's
// host.
func (h *Handler) serverMetadata(r *http.Request) map[string]any {
	base := externalScheme(r) + "://" + r.Host
	return map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/v1/oauth/authorize",
		"token_endpoint":                        base + "/v1/oauth/token-code",
		"device_authorization_endpoint":         base + "/v1/oauth/device_authorization",
		"userinfo_endpoint":                     base + "/v1/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"introspection_endpoint":                base + "/oauth/introspect",
		"end_session_endpoint":                  base + "/v1/oauth/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{h.Service.issuer.Alg()},
		"scopes_supported":                      scopesSupported,
		"claims_supported":                      claimsSupported(),
		"prompt_values_supported":               promptValuesSupported,
		"response_modes_supported":              responseModesSupported,
		"request_parameter_supported":           false,
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  true,
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": true,
		"request_uri_parameter_supported":       false,
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", grantTypeTokenExchange, grantTypeCIBA},
		// OpenID CIBA — poll mode only (no ping/push notification_endpoint).
		"backchannel_token_delivery_modes_supported": []string{"poll"},
		"backchannel_authentication_endpoint":        base + "/v1/oauth/bc-authorize",
		"backchannel_user_code_parameter_supported":  false,
		"code_challenge_methods_supported":           []string{"S256"},
		// Client authentication: a secret by Basic or form everywhere; "none"
		// (a public client) only where it may call, and introspection never.
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		// RFC 8707 — Resource Indicators
		"resource_indicators_supported": true,
		// RFC 9207 — the authorization response carries an `iss` parameter.
		"authorization_response_iss_parameter_supported": true,
		// Non-standard: agent tokens describe themselves with the actor_type and
		// agent_id claims rather than a sub prefix, which would break token exchange.
		"actor_types_supported": []string{"user", "service", "agent"},
	}
}

// scopesSupported is every scope an application may request.
var scopesSupported = []string{"openid", "profile", "email", "phone"}

// protectedResourceMetadata implements RFC 9728 §3 — OAuth 2.0 Protected
// Resource Metadata. MCP authorization servers must advertise this document
// so MCP clients can discover the resource's authorization server and
// supported token types without out-of-band configuration.
func (h *Handler) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	base := externalScheme(r) + "://" + r.Host
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"resource":                              base,
		"authorization_servers":                 []string{base},
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{h.Service.issuer.Alg()},
		"resource_documentation":                "https://docs.qeet.in/id/api-reference",
		"scopes_supported":                      scopesSupported,
	})
}

// jwks publishes the public signing keys (active + any retired key still in its
// rotation grace window) so any relying party can verify Qeet-issued ID/access
// tokens. Keys are ES256 over EC P-256; each `kid` matches the token's `kid`
// header (an RFC 7638 JWK thumbprint).
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": h.Service.issuer.JWKS()})
}

// =====================================================================
// OAuth 2.0 token revocation (RFC 7009) & introspection (RFC 7662)
// =====================================================================

// RevokeToken implements RFC 7009 for refresh tokens: it ends the whole grant,
// every rotation included, and audits it. An access token is refused with
// unsupported_token_type because it can't be revoked. An unknown token, or
// another client's, is a no-op success (RFC 7009 §2.2).
func (s *Service) RevokeToken(ctx context.Context, clientID, clientSecret, token, hint string) error {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	if token == "" {
		return nil
	}
	// Whatever its audience: a token issued for a registered resource is an
	// access token too.
	if _, err := s.issuer.VerifyAccessAnyAudience(token); err == nil {
		return oauthErr("unsupported_token_type", "access tokens can't be revoked; they expire on their own")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ended, err := s.q.WithTx(tx).RevokeRefreshTokenGrant(ctx, dbgen.RevokeRefreshTokenGrantParams{
		TokenHash: tokens.HashRefresh(token),
		ClientID:  clientID,
	})
	if err != nil {
		return err
	}
	if len(ended) == 0 {
		return nil
	}
	first := ended[0]
	tenantID, userID := first.TenantID, first.UserID
	var grantID *uuid.UUID
	if first.GrantID.Valid {
		g := uuid.UUID(first.GrantID.Bytes)
		grantID = &g
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "client",
		Action: "oidc.grant_revoked", ResourceType: "oidc_grant", ResourceID: grantID,
		IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{
			"client_id": client.ClientID, "tokens_revoked": len(ended), "via": "revocation_endpoint",
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Introspect implements RFC 7662. After client authentication it reports
// whether the token is active and, if so, its metadata. It recognises both our
// ES256 access tokens (verified statelessly) and stored OIDC refresh tokens.
// token_type_hint, when given, picks which check to run first/only.
func (s *Service) Introspect(ctx context.Context, clientID, clientSecret, token, hint string) (map[string]any, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return nil, err
	}
	inactive := map[string]any{"active": false}
	if token == "" {
		return inactive, nil
	}

	// RFC 7662 §2.1: the token must have been issued to the calling client, or this
	// endpoint becomes a token oracle for other tenants. A mismatch returns
	// active: false, which reveals nothing.
	caller, err := s.q.GetClientName(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Access token (stateless JWT) — unless the hint says it's a refresh token.
	// Whatever its audience: a token issued for a resource is still ours.
	if hint != "refresh_token" {
		if claims, err := s.issuer.VerifyAccessAnyAudience(token); err == nil {
			if claims.TenantID != caller.TenantID {
				return inactive, nil
			}
			// Only the application the token was issued to, or the service a
			// registered resource it names says serves it, may see it.
			allowed, err := s.mayIntrospect(ctx, caller.TenantID, clientID, claims)
			if err != nil {
				return nil, err
			}
			if !allowed {
				s.auditIntrospectionRefused(ctx, caller.TenantID, clientID, claims.ClientID)
				return inactive, nil
			}
			// Introspection is authoritative on revocation: a token whose account,
			// membership or agent is no longer active is inactive here, even though its
			// signature still verifies.
			live, err := s.tokenSubjectLive(ctx, claims)
			if err != nil {
				return nil, err
			}
			if !live {
				return inactive, nil
			}
			out := map[string]any{
				"active":     true,
				"token_type": "Bearer",
				"sub":        claims.Subject,
				"scope":      claims.Scope,
				"iss":        s.issuer.JWTIssuer(),
				"aud":        audienceClaim(claims.Audience),
			}
			if claims.ClientID != "" {
				out["client_id"] = claims.ClientID
			}
			if res := resourcesOf(claims.Audience, s.issuer.JWTAudience()); len(res) > 0 {
				out["resource"] = audienceClaim(res)
			}
			if claims.ExpiresAt != nil {
				out["exp"] = claims.ExpiresAt.Unix()
			}
			if claims.IssuedAt != nil {
				out["iat"] = claims.IssuedAt.Unix()
			}
			if claims.TenantID != uuid.Nil {
				out["tenant_id"] = claims.TenantID
			}
			if claims.SessionID != uuid.Nil {
				out["sid"] = claims.SessionID
			}
			// Actor context so resource/MCP servers can authorize non-user
			// principals distinctly (agent vs service) and see delegation.
			if claims.ActorType != "" {
				out["actor_type"] = claims.ActorType
			}
			if claims.AgentID != "" {
				out["agent_id"] = claims.AgentID
			}
			if claims.Act != nil && claims.Act.Subject != "" {
				out["act"] = map[string]any{"sub": claims.Act.Subject}
			}
			return out, nil
		}
	}

	// Refresh token (opaque, stored hashed) — unless the hint says access_token.
	if hint != "access_token" {
		row, err := s.q.GetRefreshTokenForIntrospect(ctx, tokens.HashRefresh(token))
		if errors.Is(err, pgx.ErrNoRows) {
			return inactive, nil
		}
		if err != nil {
			return nil, err
		}
		// Active = not revoked, not yet rotated (used), and unexpired.
		if row.RevokedAt.Valid || row.UsedAt.Valid || !time.Now().Before(row.ExpiresAt) {
			return inactive, nil
		}
		// Refresh tokens record their issuing client, so bind exactly — this is
		// the same check RevokeToken already performs.
		if row.ClientID != clientID {
			return inactive, nil
		}
		return map[string]any{
			"active":     true,
			"token_type": "refresh_token",
			"client_id":  row.ClientID,
			"sub":        row.UserID,
			"tenant_id":  row.TenantID,
			"scope":      strings.Join(row.Scopes, " "),
			"iat":        row.IssuedAt.Unix(),
			"exp":        row.ExpiresAt.Unix(),
		}, nil
	}

	return inactive, nil
}

// =====================================================================
// OAuth grant administration (live OIDC refresh-token grants)
// =====================================================================

// Grant is the current (non-revoked, non-rotated, unexpired) refresh token in
// an OIDC authorization_code grant chain — what an admin sees as an active
// "access token" for a (client, user) pair.
type Grant struct {
	ID        uuid.UUID `json:"id"`
	ClientID  string    `json:"client_id"`
	UserID    uuid.UUID `json:"user_id"`
	UserEmail string    `json:"user_email"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) ListGrants(ctx context.Context, tenantID uuid.UUID) ([]Grant, error) {
	rows, err := s.q.ListGrants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Grant, len(rows))
	for i, r := range rows {
		out[i] = Grant{
			ID: r.ID, ClientID: r.ClientID, UserID: r.UserID, UserEmail: r.UserEmail,
			Scopes: r.Scopes, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		}
	}
	return out, nil
}

// RevokeGrant revokes the entire (client, user) refresh-token chain the given
// token belongs to, so a rotated sibling can't keep the grant alive. Returns
// the client_id for the audit row.
func (s *Service) RevokeGrant(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, uuid.UUID, error) {
	q := s.q.WithTx(tx)
	row, err := q.GetGrantForRevoke(ctx, dbgen.GetGrantForRevokeParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrOIDCGrantNotFound
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := q.RevokeGrantChain(ctx, dbgen.RevokeGrantChainParams{
		ClientID: row.ClientID, UserID: row.UserID, TenantID: tenantID,
	}); err != nil {
		return "", uuid.Nil, err
	}
	return row.ClientID, row.UserID, nil
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrOIDCTenantIDInvalid
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrOIDCTenantMismatch
	}
	return scope, nil
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListGrants(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrOIDCIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	clientID, targetUser, err := h.Service.RevokeGrant(ctx, tx, tenantID, id)
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
		}
	}
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oauth.grant_revoked", ResourceType: "oidc_grant", ResourceID: &targetUser,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"client_id": clientID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
