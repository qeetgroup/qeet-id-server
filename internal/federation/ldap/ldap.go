// Package ldap signs people in against on-prem Active Directory and LDAPv3
// directories: it binds as the connection's service account, finds the user
// under the base DN, then binds as that user to check the password, creating
// the Qeet ID user on first sign-in. A scheduled sync (sync.go) suspends the
// people a directory disables or removes.
package ldap

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
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
	ID                  uuid.UUID  `json:"id"`
	OrganizationID      uuid.UUID  `json:"organization_id"`
	Name                string     `json:"name"`
	ServerURL           string     `json:"server_url"`
	StartTLS            bool       `json:"start_tls"`
	SkipTLSVerify       bool       `json:"skip_tls_verify"`
	BindDN              string     `json:"bind_dn"`
	BaseDN              string     `json:"base_dn"`
	UserFilter          string     `json:"user_filter"`
	EmailAttribute      string     `json:"email_attribute"`
	NameAttribute       string     `json:"name_attribute"`
	Status              string     `json:"status"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastLoginAt         *time.Time `json:"last_login_at"`
	SyncIntervalMinutes int        `json:"sync_interval_minutes"`
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
	auth     *authentication.Service
	egress   *egress.Policy
	box      *envelope.Cipher
	gate     entitlements.PlanGate
	observer OperationObserver
	mapper   ProfileMapper
	signals  *sessionsignal.Signaller
	notifier notification.Notifier
	link     *provision.Flow
	// allowInsecureTLS lets a connection skip certificate verification or TLS.
	allowInsecureTLS bool
}

// Deps are what the LDAP service is built from. All but AllowSkipTLSVerify
// are required.
type Deps struct {
	Pool     *pgxpool.Pool
	Auth     *authentication.Service
	Cipher   *envelope.Cipher         // seals the connections' bind passwords
	Gate     entitlements.PlanGate    // whether the plan includes LDAP
	Mapper   ProfileMapper            // the attribute mappings signed-in accounts get
	Observer OperationObserver        // records each directory operation
	Egress   *egress.Policy           // the outbound policy directories are dialled under
	Signals  *sessionsignal.Signaller // announces the sessions a sync's suspensions end
	Notifier notification.Notifier    // tells connection managers when syncs fail and recover
	// AllowInsecureTLS lets connections skip verifying the directory's
	// certificate, or skip TLS, on a developer workstation (SERVICE_ENV=dev)
	// only. Elsewhere such a connection is refused: binds send passwords.
	AllowInsecureTLS bool
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
	case d.Signals == nil:
		return nil, errors.New("ldap: missing Signals")
	case d.Notifier == nil:
		return nil, errors.New("ldap: missing Notifier")
	}
	s := &Service{
		pool: d.Pool, q: dbgen.New(d.Pool), auth: d.Auth, egress: d.Egress, box: d.Cipher, gate: d.Gate,
		observer: d.Observer, mapper: d.Mapper, allowInsecureTLS: d.AllowInsecureTLS,
		signals: d.Signals, notifier: d.Notifier,
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
	if skip && !s.allowInsecureTLS {
		return ErrTLSVerifyRequired
	}
	return nil
}

// encrypted reports whether serverURL is ldaps://, or ldap:// with StartTLS.
func encrypted(serverURL string, startTLS bool) bool {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "ldaps":
		return true
	case "ldap":
		return startTLS
	}
	return false
}

// checkTransport refuses a connection without TLS where that isn't allowed.
func (s *Service) checkTransport(serverURL string, startTLS bool) error {
	if !s.allowInsecureTLS && !encrypted(serverURL, startTLS) {
		return ErrTLSRequired
	}
	return nil
}

// requireTLS is checkTransport for using c, auditing a refusal: connections
// saved before TLS was required still exist.
func (s *Service) requireTLS(ctx context.Context, c *connFull, operation string, actor audit.Actor) error {
	err := s.checkTransport(c.ServerURL, c.StartTLS)
	if err == nil {
		return nil
	}
	meta := map[string]any{"reason": CodeTLSRequired, "operation": operation, "server": hostOnly(c.ServerURL)}
	if rerr := audit.RecordAlone(context.WithoutCancel(ctx), s.pool,
		actor.Event(c.OrganizationID, "ldap.connection_refused", "ldap_connection", c.ID, meta)); rerr != nil {
		slog.Warn("record a refused directory connection", "organization_id", c.OrganizationID, "connection_id", c.ID, "err", rerr)
	}
	return err
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
