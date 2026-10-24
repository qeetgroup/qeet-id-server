package oidc

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Client is a registered OAuth client, without its secret.
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

// CreateClientInput is what RegisterClient takes.
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

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an OIDC mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// checkClientLimit refuses with ErrPlanLimit once the tenant's plan cap for
// applications is reached. It reads on the pool, so the handlers run it before
// they open the transaction RegisterClient joins.
func (s *Service) checkClientLimit(ctx context.Context, tenantID uuid.UUID) error {
	if s.limits == nil {
		return nil
	}
	lim, err := s.limits.Limit(ctx, tenantID, "apps")
	if err != nil || lim < 0 {
		return err
	}
	n, err := s.q.CountOIDCClientsByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if int(n) >= lim {
		return errs.ErrPlanLimit.WithMetadata(map[string]any{"resource": "apps", "limit": lim})
	}
	return nil
}

// RegisterClient registers an application in tx. Callers check the plan cap
// first, with checkClientLimit.
func (s *Service) RegisterClient(ctx context.Context, tx pgx.Tx, in CreateClientInput) (*Client, string, error) {
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
		hash := password.HashSecret(secret)
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
