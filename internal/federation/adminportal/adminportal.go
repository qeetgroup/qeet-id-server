// Package adminportal implements capability-scoped, account-less SAML, SCIM
// and domain administration. A one-time link token is exchanged for a
// short-lived browser session cookie; subsequent requests never carry
// credentials in their URL.
package adminportal

import (
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/branding"
)

const (
	CapabilitySAML               = "saml"
	CapabilitySCIM               = "scim"
	CapabilityDomainVerification = "domain_verification" // prove the organization owns a domain

	minTTL              = 15 * time.Minute
	maxTTL              = 24 * time.Hour
	defaultTTL          = time.Hour
	portalSessionTTL    = 30 * time.Minute
	portalSessionCookie = "qeet_admin_portal_session"
	portalCookiePath    = "/v1/admin-portal"
)

// SessionCookie names the portal session cookie.
const SessionCookie = portalSessionCookie

var validCapabilities = []string{CapabilitySAML, CapabilitySCIM, CapabilityDomainVerification}

// Link is an admin-portal link, without its token.
type Link struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Capabilities   []string   `json:"capabilities"`
	CreatedBy      *uuid.UUID `json:"created_by"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Has reports whether the link authorizes the given capability.
func (l Link) Has(capability string) bool { return slices.Contains(l.Capabilities, capability) }

// Service manages the portal links.
type Service struct {
	pool         *pgxpool.Pool
	q            *dbgen.Queries
	brandingRepo branding.LoginBrandingReader
	loginBaseURL string
}

// NewService returns the admin portal service.
func NewService(pool *pgxpool.Pool, brandingRepo branding.LoginBrandingReader, loginBaseURL string) *Service {
	return &Service{
		pool:         pool,
		q:            dbgen.New(pool),
		brandingRepo: brandingRepo,
		loginBaseURL: strings.TrimRight(loginBaseURL, "/"),
	}
}
