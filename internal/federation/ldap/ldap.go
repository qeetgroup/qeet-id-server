// Package ldap signs people in against on-prem Active Directory and LDAPv3
// directories: it binds as the connection's service account, finds the user
// under the base DN, then binds as that user to check the password, creating
// the Qeet ID user on first sign-in.
package ldap

import (
	"context"
	"errors"
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

// Service manages LDAP connections and directory sign-in.
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
	// allowSkipVerify lets a connection turn certificate verification off.
	allowSkipVerify bool
}

// Deps are what the LDAP service is built from. All but AllowSkipTLSVerify
// are required.
type Deps struct {
	Pool     *pgxpool.Pool
	Auth     *auth.Service
	Cipher   *envelope.Cipher      // seals the connections' bind passwords
	Gate     entitlements.PlanGate // whether the plan includes LDAP
	Mapper   ProfileMapper         // the attribute mappings signed-in accounts get
	Observer OperationObserver     // records each directory operation
	Egress   *egress.Policy        // the outbound policy directories are dialled under
	// AllowSkipTLSVerify lets connections turn off verification of the
	// directory's certificate, for a developer workstation (SERVICE_ENV=dev)
	// only. Otherwise saving or binding such a connection is refused.
	AllowSkipTLSVerify bool
}

// NewService returns the LDAP service built from d, or an error naming the
// dependency d lacks.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.Pool == nil:
		return nil, errors.New("ldap: missing Pool")
	case d.Auth == nil:
		return nil, errors.New("ldap: missing Auth")
	case d.Cipher == nil:
		return nil, errors.New("ldap: missing Cipher")
	case d.Gate == nil:
		return nil, errors.New("ldap: missing Gate")
	case d.Mapper == nil:
		return nil, errors.New("ldap: missing Mapper")
	case d.Observer == nil:
		return nil, errors.New("ldap: missing Observer")
	case d.Egress == nil:
		return nil, errors.New("ldap: missing Egress")
	}
	s := &Service{
		pool: d.Pool, q: dbgen.New(d.Pool), auth: d.Auth, egress: d.Egress, box: d.Cipher, gate: d.Gate,
		observer: d.Observer, mapper: d.Mapper, allowSkipVerify: d.AllowSkipTLSVerify,
	}
	s.link = &provision.Flow{Pool: d.Pool, Method: provider, Store: s.storeMappedProfile, Recorder: d.Auth,
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
	return s, nil
}

// checkTLSVerify refuses a connection that turns certificate verification off
// where that isn't allowed.
func (s *Service) checkTLSVerify(skip bool) error {
	if skip && !s.allowSkipVerify {
		return ErrTLSVerifyRequired
	}
	return nil
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// requireLDAP refuses with errs.ErrUpgradeRequired when the organization's
// plan doesn't include LDAP.
func (s *Service) requireLDAP(ctx context.Context, organizationID uuid.UUID) error {
	ok, err := s.gate.FeatureAllowed(ctx, organizationID, "ldap")
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "ldap"})
	}
	return nil
}
