// Package oidcsso signs people in through an organization's own OpenID Connect identity provider
// (Microsoft Entra ID, Okta, Google Workspace): an authorization-code sign-in with PKCE, state and
// nonce, bound to the browser that began it, whose ID token is checked against the provider's keys.
// Accounts are linked and adopted by the rules SAML sign-in follows.
package oidcsso

import (
	"context"
	"errors"
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
// people in through them.
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
	// The hosted login's origin and the addresses a sign-in it starts may
	// return to.
	loginBaseURL string
	returnTo     returnto.Allowed
}

// Deps are what the service is built from. All are required but
// LoginBaseURL and ReturnOrigins.
type Deps struct {
	Pool       *pgxpool.Pool
	Auth       *auth.Service
	Cipher     *envelope.Cipher      // seals the connections' client secrets
	Gate       entitlements.PlanGate // whether the plan includes single sign-on
	Egress     *egress.Policy        // the outbound policy providers are reached under
	AppBaseURL string                // where the console's callback is served
	// LoginBaseURL lets a sign-in start on the hosted login: its answer goes
	// back to that sign-in page, and its return_to must be a path or on one of
	// ReturnOrigins. With none, no sign-in starts there.
	LoginBaseURL  string
	ReturnOrigins []string
}

// NewService returns the service built from d, or an error naming the
// dependency d lacks.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.Pool == nil:
		return nil, errors.New("oidcsso: missing Pool")
	case d.Auth == nil:
		return nil, errors.New("oidcsso: missing Auth")
	case d.Cipher == nil:
		return nil, errors.New("oidcsso: missing Cipher")
	case d.Gate == nil:
		return nil, errors.New("oidcsso: missing Gate")
	case d.Egress == nil:
		return nil, errors.New("oidcsso: missing Egress")
	case d.AppBaseURL == "":
		return nil, errors.New("oidcsso: missing AppBaseURL")
	}
	return &Service{
		pool:         d.Pool,
		q:            dbgen.New(d.Pool),
		auth:         d.Auth,
		box:          d.Cipher,
		gate:         d.Gate,
		egress:       d.Egress,
		providers:    oidcrp.New(d.Egress),
		appBaseURL:   strings.TrimRight(d.AppBaseURL, "/"),
		loginBaseURL: strings.TrimRight(d.LoginBaseURL, "/"),
		returnTo:     returnto.Origins(d.ReturnOrigins...),
		link: &provision.Flow{Pool: d.Pool, Method: provider, Recorder: d.Auth, Errors: provision.Errors{
			NotHome:            ErrUserOrganizationMismatch,
			EmailMissing:       ErrNoEmail,
			AccountUnverified:  ErrAccountUnverified,
			AccountAdministers: ErrAccountAdministers,
			DomainUnverified:   ErrEmailDomainUnverified,
			EmailUnverified:    ErrEmailUnverified,
			JITNotAllowed:      ErrJITNotAllowed,
		}},
	}, nil
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// RequireSSO refuses with ErrUpgradeRequired when the organization's plan doesn't
// include enterprise single sign-on. It reads on the pool, so a handler runs
// it before opening the transaction Create joins.
func (s *Service) RequireSSO(ctx context.Context, organizationID uuid.UUID) error {
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
