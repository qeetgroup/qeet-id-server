// Package oidcsso signs people in through an organization's own OpenID Connect
// identity provider, such as Microsoft Entra ID, Okta or Google Workspace: an
// authorization-code sign-in with PKCE, state and nonce, bound to the browser
// that began it, whose ID token is checked against the provider's published
// keys. Accounts are linked and adopted by the rules SAML sign-in follows.
package oidcsso

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/returnto"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	provider      = "oidc"            // the external identities' provider, and the sessions' sign-in method
	secretPurpose = "oidc-connection" // envelope purpose of a connection's client secret
	planFeature   = "sso"             // the plan feature a connection needs
	maxScopes     = 20
	maxTenantIDs  = 50
	maxClaimLen   = 200
)

// defaultScopes are asked for when a connection names none.
var defaultScopes = []string{"openid", "email", "profile"}

// ClaimMapping names the ID token claims a sign-in reads; "" reads none, except
// for Email, which is required.
type ClaimMapping struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Groups     string `json:"groups"`
}

// Connection is an organization's connection to its own OpenID Connect
// provider. The client secret is never returned. RedirectURI is where the
// provider must send the browser back, filled in by the handler.
type Connection struct {
	ID                  uuid.UUID    `json:"id"`
	OrganizationID      uuid.UUID    `json:"organization_id"`
	Name                string       `json:"name"`
	Issuer              string       `json:"issuer"`
	DiscoveryURL        string       `json:"discovery_url"`
	ClientID            string       `json:"client_id"`
	Scopes              []string     `json:"scopes"`
	AllowedIdPTenantIDs []string     `json:"allowed_idp_tenant_ids"`
	ClaimMapping        ClaimMapping `json:"claim_mapping"`
	Status              string       `json:"status"`
	RedirectURI         string       `json:"redirect_uri,omitempty"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
	LastLoginAt         *time.Time   `json:"last_login_at"`
}

// discoveryURL is where the provider's discovery document is read.
func (c *Connection) discoveryURL() string {
	if c.DiscoveryURL != "" {
		return c.DiscoveryURL
	}
	return strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
}

// Service manages an organization's OpenID Connect connections and signs
// people in through them. A nil gate leaves connection creation ungated.
type Service struct {
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	auth       *auth.Service
	box        *envelope.Cipher
	gate       entitlements.PlanGate
	egress     *egress.Policy
	providers  *oidcrp.Client
	link       *provision.Flow
	appBaseURL string
	// The hosted login's origin and the addresses a sign-in it starts may return to (SetHostedLogin).
	loginBaseURL string
	returnTo     returnto.Allowed
}

// SetHostedLogin lets a sign-in start on the hosted login: its answer goes back to
// loginBaseURL's sign-in page, and its return_to must be a path or on one of origins.
func (s *Service) SetHostedLogin(loginBaseURL string, origins ...string) {
	s.loginBaseURL = strings.TrimRight(loginBaseURL, "/")
	s.returnTo = returnto.Origins(origins...)
}

// NewService returns the service. Outbound requests to providers follow the
// first policy given, else the default public-only one.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string, policies ...*egress.Policy) *Service {
	policy := egress.PublicPolicy(policies...)
	s := &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		egress:     policy,
		providers:  oidcrp.New(policy),
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
		link: &provision.Flow{Pool: pool, Method: provider, Errors: provision.Errors{
			NotHome:            ErrUserOrganizationMismatch,
			EmailMissing:       ErrNoEmail,
			AccountUnverified:  ErrAccountUnverified,
			AccountAdministers: ErrAccountAdministers,
			DomainUnverified:   ErrEmailDomainUnverified,
			EmailUnverified:    ErrEmailUnverified,
			JITNotAllowed:      ErrJITNotAllowed,
		}},
	}
	if authSvc != nil {
		s.link.Recorder = authSvc
	}
	return s
}

// SetCipher sets the cipher that seals client secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g entitlements.PlanGate) { s.gate = g }

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// RequireSSO refuses with ErrUpgradeRequired when the organization's plan doesn't
// include enterprise single sign-on. It reads on the pool, so a handler runs
// it before opening the transaction Create joins.
func (s *Service) RequireSSO(ctx context.Context, organizationID uuid.UUID) error {
	if s.gate == nil {
		return nil
	}
	ok, err := s.gate.FeatureAllowed(ctx, organizationID, planFeature)
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": planFeature})
	}
	return nil
}

// toConnection maps a generated row to a Connection. The other connection
// queries return rows with the same fields, which convert to GetOidcConnectionRow.
func toConnection(r dbgen.GetOidcConnectionRow) *Connection {
	return &Connection{
		ID:                  r.ID,
		OrganizationID:      r.OrganizationID,
		Name:                r.Name,
		Issuer:              r.Issuer,
		DiscoveryURL:        r.DiscoveryUrl,
		ClientID:            r.ClientID,
		Scopes:              r.Scopes,
		AllowedIdPTenantIDs: r.AllowedIdpTenantIds,
		ClaimMapping: ClaimMapping{
			Email:      r.EmailClaim,
			Name:       r.NameClaim,
			GivenName:  r.GivenNameClaim,
			FamilyName: r.FamilyNameClaim,
			Groups:     r.GroupsClaim,
		},
		Status:      r.Status,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		LastLoginAt: r.LastLoginAt,
	}
}
