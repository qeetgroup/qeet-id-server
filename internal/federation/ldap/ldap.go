// Package ldap signs people in against on-prem Active Directory and LDAPv3
// directories: it binds as the connection's service account, finds the user
// under the base DN, then binds as that user to check the password, creating
// the Qeet ID user on first sign-in.
package ldap

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	provider    = "ldap"
	dialTimeout = 6 * time.Second
	groupsAttr  = "memberOf" // the groups read when no mapping targets groups
)

// Connection is the API-facing view — bind_password is deliberately omitted.
type Connection struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Name           string     `json:"name"`
	ServerURL      string     `json:"server_url"`
	StartTLS       bool       `json:"start_tls"`
	SkipTLSVerify  bool       `json:"skip_tls_verify"`
	BindDN         string     `json:"bind_dn"`
	BaseDN         string     `json:"base_dn"`
	UserFilter     string     `json:"user_filter"`
	EmailAttribute string     `json:"email_attribute"`
	NameAttribute  string     `json:"name_attribute"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastLoginAt    *time.Time `json:"last_login_at"`
}

// connFull adds the service-account secret needed to dial; never serialised.
type connFull struct {
	Connection
	BindPassword string
}

// Service manages LDAP connections and directory sign-in. A nil gate leaves
// connection creation ungated.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	auth     *auth.Service
	egress   *egress.Policy
	box      *envelope.Cipher
	gate     entitlements.PlanGate
	observer OperationObserver
	mapper   ProfileMapper
	link     *provision.Flow
	// allowSkipVerify lets a connection turn certificate verification off;
	// see SetAllowSkipTLSVerify.
	allowSkipVerify bool
}

// NewService returns the LDAP service.
func NewService(pool *pgxpool.Pool, authSvc *auth.Service, policies ...*egress.Policy) *Service {
	s := &Service{pool: pool, q: dbgen.New(pool), auth: authSvc, egress: egress.PublicPolicy(policies...)}
	s.link = &provision.Flow{Pool: pool, Method: provider, Store: s.storeMappedProfile,
		Errors: provision.Errors{
			NotHome:            ErrAccountNotInOrganization,
			EmailMissing:       ErrEmailAttributeMissing,
			AccountUnverified:  ErrAccountUnverified,
			AccountAdministers: ErrAccountAdministers,
			DomainUnverified:   ErrEmailDomainUnverified,
			// A directory has no word on whether an address is verified.
			EmailUnverified: ErrEmailDomainUnverified,
			JITNotAllowed:   ErrJITNotAllowed,
		}}
	if authSvc != nil {
		s.link.Recorder = authSvc
	}
	return s
}

// SetCipher sets the cipher that encrypts LDAP secrets at rest.
func (s *Service) SetCipher(box *envelope.Cipher) { s.box = box }

// SetAllowSkipTLSVerify lets connections turn off verification of the
// directory's certificate, for a developer workstation (SERVICE_ENV=dev) only.
// Otherwise saving or binding such a connection is refused.
func (s *Service) SetAllowSkipTLSVerify(allow bool) { s.allowSkipVerify = allow }

// checkTLSVerify refuses a connection that turns certificate verification off
// where that isn't allowed.
func (s *Service) checkTLSVerify(skip bool) error {
	if skip && !s.allowSkipVerify {
		return ErrTLSVerifyRequired
	}
	return nil
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g entitlements.PlanGate) { s.gate = g }

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// requireLDAP refuses with errs.ErrUpgradeRequired when the gate, if set,
// finds that the organization's plan doesn't include LDAP.
func (s *Service) requireLDAP(ctx context.Context, organizationID uuid.UUID) error {
	if s.gate == nil {
		return nil
	}
	ok, err := s.gate.FeatureAllowed(ctx, organizationID, "ldap")
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "ldap"})
	}
	return nil
}
