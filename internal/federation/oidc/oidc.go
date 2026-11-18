// Package oidc implements Qeet's OpenID Connect provider role: the OAuth2/OIDC
// grants (authorization_code+PKCE, refresh, client_credentials, token-exchange,
// device, CIBA) at one token endpoint, plus discovery, JWKS, and userinfo
// endpoints.
package oidc

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Service is the OpenID Connect provider: clients, grants and tokens.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
	// notifier delivers the CIBA async consent prompt. See ciba.go.
	notifier notification.Notifier
	// limits gates application (relying-party) registration by plan.
	limits entitlements.PlanLimiter
	// grantMaxAge ends a grant that long after it starts however often it is
	// renewed, where its organization sets no maximum session age of its own.
	grantMaxAge time.Duration
	// addresses is the organizations' address rules. See address.go.
	addresses ipallow.AddressPolicy
	// sessionFactors is the second factor an organization still requires of a
	// person's session.
	sessionFactors func(ctx context.Context, sessionID, userID, organizationID uuid.UUID) error
	// lockout bounds wrong application secrets. See client_lockout.go.
	lockout ClientLockout
	// logoutClient sends back-channel sign-out notices under logoutEgress
	// (the SSRF guard). See logout.go.
	logoutClient *http.Client
	logoutEgress *egress.Policy
	// agentStatus returns an AI agent's lifecycle status, so introspection
	// reports a suspended agent's tokens inactive.
	agentStatus func(ctx context.Context, agentID uuid.UUID) (string, error)
	// sessionLive reports whether a user's own session has not ended, so its
	// access tokens introspect inactive and can't be exchanged once it has.
	sessionLive func(ctx context.Context, sessionID, userID uuid.UUID) (bool, error)
	// principalLive reports whether a service principal exists and isn't
	// disabled, so its tokens introspect inactive once it is.
	principalLive func(ctx context.Context, principalID uuid.UUID) (bool, error)
	// machineClients are the machine identities the client_credentials grant
	// serves. See ClientCredentials.
	machineClients []MachineClient
	// webOrigins caches every application's web origins for the CORS check
	// (see weborigins.go).
	webOrigins originCache
}

// Deps are what the OpenID provider is built from. All are required but
// MachineClients and Lockout.
type Deps struct {
	Pool   *pgxpool.Pool
	Issuer *tokens.Issuer
	// Addresses are the address rules checked when a person signs in to an
	// application: authorization codes, device approval and device token
	// collection, not code redemption or refresh, which come from its server.
	Addresses ipallow.AddressPolicy
	Egress    *egress.Policy           // back-channel sign-out notices go out under it
	Notifier  notification.Notifier    // delivers the CIBA consent prompt
	Limits    entitlements.PlanLimiter // the plan's cap on applications
	// AgentStatus, SessionLive and PrincipalLive say whether a token's agent,
	// a person's own session and a service principal are still live, for
	// introspection and token exchange.
	AgentStatus   func(ctx context.Context, agentID uuid.UUID) (string, error)
	SessionLive   func(ctx context.Context, sessionID, userID uuid.UUID) (bool, error)
	PrincipalLive func(ctx context.Context, principalID uuid.UUID) (bool, error)
	// SessionFactors is the second factor an organization still requires of a
	// person's session, which approving a backchannel request must meet.
	SessionFactors func(ctx context.Context, sessionID, userID, organizationID uuid.UUID) error
	// GrantMaxAge is how long an application's grant lasts however often it is
	// renewed, where its organization sets no maximum (config SESSION_MAX_AGE).
	GrantMaxAge time.Duration
	// MachineClients are the machine identities the client_credentials grant
	// serves, asked in order. With none it authenticates no one.
	MachineClients []MachineClient
	// Lockout bounds wrong application secrets; zero is DefaultClientLockout.
	Lockout ClientLockout
}

// NewService returns the OIDC provider built from d, or an error naming the
// dependency d lacks.
func NewService(d Deps) (*Service, error) {
	if err := d.missing(); err != nil {
		return nil, err
	}
	lockout := d.Lockout
	if lockout == (ClientLockout{}) {
		lockout = DefaultClientLockout()
	}
	return &Service{
		pool: d.Pool, q: dbgen.New(d.Pool), issuer: d.Issuer, notifier: d.Notifier, limits: d.Limits,
		grantMaxAge: d.GrantMaxAge, addresses: d.Addresses, sessionFactors: d.SessionFactors, lockout: lockout,
		logoutClient: d.Egress.HTTPClient(5 * time.Second), logoutEgress: d.Egress,
		agentStatus: d.AgentStatus, sessionLive: d.SessionLive, principalLive: d.PrincipalLive,
		machineClients: d.MachineClients,
	}, nil
}

// missing names the first required dependency d lacks.
func (d Deps) missing() error {
	var name string
	switch {
	case d.Pool == nil:
		name = "Pool"
	case d.Issuer == nil:
		name = "Issuer"
	case d.Addresses == nil:
		name = "Addresses"
	case d.Egress == nil:
		name = "Egress"
	case d.Notifier == nil:
		name = "Notifier"
	case d.Limits == nil:
		name = "Limits"
	case d.AgentStatus == nil:
		name = "AgentStatus"
	case d.SessionLive == nil:
		name = "SessionLive"
	case d.PrincipalLive == nil:
		name = "PrincipalLive"
	case d.SessionFactors == nil:
		name = "SessionFactors"
	case d.GrantMaxAge <= 0:
		name = "GrantMaxAge"
	default:
		return nil
	}
	return errors.New("oidc: missing " + name)
}

// tokenExchangeMaxDepth is how many exchanges deep a token may be exchanged
// again: an exchanged token's own exchange is the last.
const tokenExchangeMaxDepth = 2

// =====================================================================
// OAuth 2.0 token revocation (RFC 7009) & introspection (RFC 7662)
// =====================================================================

// =====================================================================
// OAuth grant administration (live OIDC refresh-token grants)
// =====================================================================
