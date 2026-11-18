// Package saml implements SAML 2.0 single sign-on in both directions. As a
// service provider it signs people in through an organization's IdP connection, using
// gosaml2 and goxmldsig to validate assertions; as an identity provider
// (idp.go) it issues signed assertions to the organization's registered SPs.
package saml

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/returnto"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	provider        = "saml"
	loginCodeTTL    = 5 * time.Minute
	authnRequestTTL = 10 * time.Minute
	replayIDTTL     = 24 * time.Hour
)

// Connection is an organization's connection to an external SAML IdP.
// AllowIdPInitiated and GroupsAttribute aren't in the generated connection
// queries, so they are read separately. GroupsAttribute names the attribute
// carrying a person's groups; "" reads the common ones (assertedGroups).
// Certificates are every signing certificate it trusts; IdpCertificate is the
// oldest of them. MetadataURL is where it refreshes its IdP settings from.
type Connection struct {
	ID                uuid.UUID     `json:"id"`
	OrganizationID    uuid.UUID     `json:"organization_id"`
	Name              string        `json:"name"`
	IdpEntityID       string        `json:"idp_entity_id"`
	IdpSSOURL         string        `json:"idp_sso_url"`
	IdpCertificate    string        `json:"idp_certificate"`
	Certificates      []Certificate `json:"certificates"`
	MetadataURL       *string       `json:"metadata_url"`
	RefreshedAt       *time.Time    `json:"metadata_refreshed_at"`
	MetadataError     *string       `json:"metadata_error"`
	EmailAttribute    string        `json:"email_attribute"`
	NameAttribute     string        `json:"name_attribute"`
	GroupsAttribute   string        `json:"groups_attribute"`
	Status            string        `json:"status"`
	AllowIdPInitiated bool          `json:"allow_idp_initiated"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
	LastLoginAt       *time.Time    `json:"last_login_at"`
}

// Service manages an organization's IdP connections and runs SP-initiated sign-in.
// nextRequestSweep and nextReplaySweep throttle deleting expired AuthnRequest and
// replay rows, separately so a busy login or ACS path can't starve the other.
// IdP metadata is fetched with metadataHTTP, within the egress policy; box
// seals the connections' SP keys.
type Service struct {
	pool             *pgxpool.Pool
	q                *dbgen.Queries
	auth             *auth.Service
	appBaseURL       string
	gate             entitlements.PlanGate
	nextRequestSweep atomic.Int64
	nextReplaySweep  atomic.Int64
	egress           *egress.Policy
	metadataHTTP     *http.Client
	box              *envelope.Cipher
	link             *provision.Flow
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

// replaySweepInterval is how often any one replica collects expired SAML
// correlation and replay rows.
const replaySweepInterval = 5 * time.Minute

// sweepDue reports whether this replica should collect now, and claims the
// slot if so. Replicas sweeping independently is harmless: the deletes are
// idempotent and touch only rows that are already past their expiry.
func sweepDue(next *atomic.Int64) bool {
	now := time.Now().Unix()
	due := next.Load()
	return now >= due && next.CompareAndSwap(due, now+int64(replaySweepInterval.Seconds()))
}

// NewService returns the SAML service.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string) *Service {
	s := &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
		link: &provision.Flow{Pool: pool, Method: provider, Errors: provision.Errors{
			NotHome:            ErrUserOrganizationMismatch,
			EmailMissing:       ErrAssertionNoEmail,
			AccountUnverified:  ErrAccountUnverified,
			AccountAdministers: ErrAccountAdministers,
			DomainUnverified:   ErrEmailDomainUnverified,
			// An assertion carries no word on whether its IdP verified the address.
			EmailUnverified: ErrEmailDomainUnverified,
			JITNotAllowed:   ErrJITNotAllowed,
		}},
	}
	if authSvc != nil {
		s.link.Recorder = authSvc
	}
	s.SetEgressPolicy(egress.PublicPolicy())
	return s
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g entitlements.PlanGate) { s.gate = g }

// RequireSSO refuses with errs.ErrUpgradeRequired when the organization's plan
// doesn't include enterprise SSO: setting up a connection and every sign-in
// through one need it. It reads on the pool, so callers run it before they
// open the transaction Create joins.
func (s *Service) RequireSSO(ctx context.Context, organizationID uuid.UUID) error {
	return requireSSO(ctx, s.gate, organizationID)
}

// toConnection maps a sqlc-generated row to the API-facing Connection type.
// The other connection queries return rows with the same fields, which
// convert to dbgen.GetSamlConnectionRow.
func toConnection(r dbgen.GetSamlConnectionRow) *Connection {
	return &Connection{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Name:           r.Name,
		IdpEntityID:    r.IdpEntityID,
		IdpSSOURL:      r.IdpSsoUrl,
		IdpCertificate: r.IdpCertificate,
		Certificates:   []Certificate{},
		EmailAttribute: r.EmailAttribute,
		NameAttribute:  r.NameAttribute,
		Status:         r.Status,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		LastLoginAt:    r.LastLoginAt,
	}
}
