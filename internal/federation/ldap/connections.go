package ldap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// connFields fills in a Connection from the shared columns returned by all
// ldap_connections queries (pubCols — no bind_password).
func connFields(c *Connection, id, organizationID uuid.UUID, name, serverURL string, startTLS, skipTLSVerify bool,
	bindDN, baseDN, userFilter, emailAttribute, nameAttribute, status string,
	createdAt, updatedAt time.Time, lastLoginAt *time.Time, syncInterval int32) {
	c.SyncIntervalMinutes = int(syncInterval)
	c.ID = id
	c.OrganizationID = organizationID
	c.Name = name
	c.ServerURL = serverURL
	c.StartTLS = startTLS
	c.SkipTLSVerify = skipTLSVerify
	c.BindDN = bindDN
	c.BaseDN = baseDN
	c.UserFilter = userFilter
	c.EmailAttribute = emailAttribute
	c.NameAttribute = nameAttribute
	c.Status = status
	c.CreatedAt = createdAt
	c.UpdatedAt = updatedAt
	c.LastLoginAt = lastLoginAt
}

// CreateInput is what Create takes.
type CreateInput struct {
	Name                string `json:"name"`
	ServerURL           string `json:"server_url"`
	StartTLS            bool   `json:"start_tls"`
	SkipTLSVerify       bool   `json:"skip_tls_verify"`
	BindDN              string `json:"bind_dn"`
	BindPassword        string `json:"bind_password"`
	BaseDN              string `json:"base_dn"`
	UserFilter          string `json:"user_filter"`
	EmailAttribute      string `json:"email_attribute"`
	NameAttribute       string `json:"name_attribute"`
	Status              string `json:"status"`
	SyncIntervalMinutes *int   `json:"sync_interval_minutes"`
}

func syncInterval(minutes *int, def int32) (int32, error) {
	if minutes == nil {
		return def, nil
	}
	if *minutes < MinSyncInterval || *minutes > MaxSyncInterval {
		return 0, ErrSyncIntervalInvalid
	}
	return int32(*minutes), nil // #nosec G115 -- 5..60
}

func defaulted(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// Create adds an LDAP connection to the organization, recorded as actor's.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, in CreateInput, actor audit.Actor) (*Connection, error) {
	if err := s.checkTransport(in.ServerURL, in.StartTLS); err != nil {
		return nil, err
	}
	if _, err := s.egress.ValidateLDAPURL(in.ServerURL, in.StartTLS); err != nil {
		return nil, ErrServerURLInvalid
	}
	if err := s.checkTLSVerify(in.SkipTLSVerify); err != nil {
		return nil, err
	}
	interval, err := syncInterval(in.SyncIntervalMinutes, DefaultSyncInterval)
	if err != nil {
		return nil, err
	}
	// Plan gate: LDAP/AD directory sync is an Enterprise feature.
	if err := s.requireLDAP(ctx, organizationID); err != nil {
		return nil, err
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(organizationID, "ldap-bind", id.String(), []byte(in.BindPassword))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	r, err := s.q.WithTx(tx).InsertLdapConnection(ctx, dbgen.InsertLdapConnectionParams{
		ID: id, OrganizationID: organizationID, Name: in.Name, ServerUrl: in.ServerURL,
		StartTls: in.StartTLS, SkipTlsVerify: in.SkipTLSVerify, BindDn: in.BindDN,
		BindPasswordCt: ciphertext, BindPasswordNonce: nonce, BaseDn: in.BaseDN,
		UserFilter: defaulted(in.UserFilter, "(uid=%s)"), EmailAttribute: defaulted(in.EmailAttribute, "mail"),
		NameAttribute: defaulted(in.NameAttribute, "cn"), Status: defaulted(in.Status, "draft"),
		SyncIntervalMinutes: interval,
	})
	if err != nil {
		return nil, err
	}
	var c Connection
	connFields(&c, r.ID, r.OrganizationID, r.Name, r.ServerUrl, r.StartTls, r.SkipTlsVerify,
		r.BindDn, r.BaseDn, r.UserFilter, r.EmailAttribute, r.NameAttribute, r.Status,
		r.CreatedAt, r.UpdatedAt, r.LastLoginAt, r.SyncIntervalMinutes)
	if err := recordChange(ctx, tx, actor, organizationID, c.ID, "ldap.connection_created", map[string]any{"name": c.Name, "server": c.ServerURL}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

// recordChange audits, in tx, actor's change to organizationID's connection id.
func recordChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, id uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "ldap_connection", id, meta))
}

// List returns the organization's LDAP connections.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListLdapConnections(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		connFields(&out[i], r.ID, r.OrganizationID, r.Name, r.ServerUrl, r.StartTls, r.SkipTlsVerify,
			r.BindDn, r.BaseDn, r.UserFilter, r.EmailAttribute, r.NameAttribute, r.Status,
			r.CreatedAt, r.UpdatedAt, r.LastLoginAt, r.SyncIntervalMinutes)
	}
	return out, nil
}

// Get returns one of the organization's LDAP connections.
func (s *Service) Get(ctx context.Context, id, organizationID uuid.UUID) (*Connection, error) {
	r, err := s.q.GetLdapConnection(ctx, dbgen.GetLdapConnectionParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c Connection
	connFields(&c, r.ID, r.OrganizationID, r.Name, r.ServerUrl, r.StartTls, r.SkipTlsVerify,
		r.BindDn, r.BaseDn, r.UserFilter, r.EmailAttribute, r.NameAttribute, r.Status,
		r.CreatedAt, r.UpdatedAt, r.LastLoginAt, r.SyncIntervalMinutes)
	return &c, nil
}

// getFull loads a connection including its bind secret. organizationID may be
// uuid.Nil to read it by ID alone: the public sign-in routes name the
// connection in their path.
func (s *Service) getFull(ctx context.Context, id, organizationID uuid.UUID) (*connFull, error) {
	r, err := s.q.GetLdapConnectionWithSecret(ctx, dbgen.GetLdapConnectionWithSecretParams{ID: id, OrganizationID: postgres.NullIfZero(organizationID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c connFull
	connFields(&c.Connection, r.ID, r.OrganizationID, r.Name, r.ServerUrl, r.StartTls, r.SkipTlsVerify,
		r.BindDn, r.BaseDn, r.UserFilter, r.EmailAttribute, r.NameAttribute, r.Status,
		r.CreatedAt, r.UpdatedAt, r.LastLoginAt, r.SyncIntervalMinutes)
	plain, err := s.box.Open(c.OrganizationID, "ldap-bind", c.ID.String(), r.BindPasswordCt, r.BindPasswordNonce)
	if err != nil {
		return nil, err
	}
	c.BindPassword = string(plain)
	return &c, nil
}

// UpdateInput is what Update takes.
type UpdateInput struct {
	Name                *string `json:"name"`
	ServerURL           *string `json:"server_url"`
	StartTLS            *bool   `json:"start_tls"`
	SkipTLSVerify       *bool   `json:"skip_tls_verify"`
	BindDN              *string `json:"bind_dn"`
	BindPassword        *string `json:"bind_password"`
	BaseDN              *string `json:"base_dn"`
	UserFilter          *string `json:"user_filter"`
	EmailAttribute      *string `json:"email_attribute"`
	NameAttribute       *string `json:"name_attribute"`
	Status              *string `json:"status"`
	SyncIntervalMinutes *int    `json:"sync_interval_minutes"`
}

// ChangesTrust reports whether in changes what c trusts: the directory it asks,
// how it reaches it, and which of its entries it reads.
func (in UpdateInput) ChangesTrust(c *Connection) bool {
	differs := func(p *string, current string) bool { return p != nil && strings.TrimSpace(*p) != current }
	if differs(in.ServerURL, c.ServerURL) || differs(in.BindDN, c.BindDN) || differs(in.BaseDN, c.BaseDN) || differs(in.UserFilter, c.UserFilter) {
		return true
	}
	return (in.StartTLS != nil && *in.StartTLS != c.StartTLS) || (in.SkipTLSVerify != nil && *in.SkipTLSVerify != c.SkipTLSVerify)
}

// Update changes one of the organization's LDAP connections, recorded as actor's.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor) (*Connection, error) {
	if in.ServerURL != nil {
		if _, err := s.egress.ValidateLDAPURL(*in.ServerURL, true); err != nil {
			return nil, ErrServerURLInvalid
		}
	}
	if in.SkipTLSVerify != nil {
		if err := s.checkTLSVerify(*in.SkipTLSVerify); err != nil {
			return nil, err
		}
	}
	var interval *int32
	if in.SyncIntervalMinutes != nil {
		minutes, err := syncInterval(in.SyncIntervalMinutes, 0)
		if err != nil {
			return nil, err
		}
		interval = &minutes
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	bindPassword := in.BindPassword
	r, err := q.UpdateLdapConnection(ctx, dbgen.UpdateLdapConnectionParams{
		ID:                  id,
		OrganizationID:      organizationID,
		Name:                in.Name,
		ServerUrl:           in.ServerURL,
		StartTls:            in.StartTLS,
		SkipTlsVerify:       in.SkipTLSVerify,
		BindDn:              in.BindDN,
		BaseDn:              in.BaseDN,
		UserFilter:          in.UserFilter,
		EmailAttribute:      in.EmailAttribute,
		NameAttribute:       in.NameAttribute,
		Status:              in.Status,
		SyncIntervalMinutes: interval,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// A connection saved before verification was required keeps it off until
	// changed; it can't be saved again that way.
	if err := s.checkTLSVerify(r.SkipTlsVerify); err != nil {
		return nil, err
	}
	// One saved before TLS was required can still be turned off.
	if r.Status != "disabled" {
		if err := s.checkTransport(r.ServerUrl, r.StartTls); err != nil {
			return nil, err
		}
	}
	// Saving re-baselines the sync, so an administrator can accept a directory that really shrank.
	if err := q.ResetLdapSync(ctx, dbgen.ResetLdapSyncParams{ID: id, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if bindPassword != nil {
		ciphertext, nonce, sealErr := s.box.Seal(organizationID, "ldap-bind", id.String(), []byte(*bindPassword))
		if sealErr != nil {
			return nil, sealErr
		}
		if err := q.SetLdapBindPassword(ctx, dbgen.SetLdapBindPasswordParams{
			ID: id, OrganizationID: organizationID, BindPasswordCt: ciphertext, BindPasswordNonce: nonce,
		}); err != nil {
			return nil, err
		}
	}
	var c Connection
	connFields(&c, r.ID, r.OrganizationID, r.Name, r.ServerUrl, r.StartTls, r.SkipTlsVerify,
		r.BindDn, r.BaseDn, r.UserFilter, r.EmailAttribute, r.NameAttribute, r.Status,
		r.CreatedAt, r.UpdatedAt, r.LastLoginAt, r.SyncIntervalMinutes)
	if err := recordChange(ctx, tx, actor, organizationID, c.ID, "ldap.connection_updated", map[string]any{"status": c.Status}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

// Delete removes one of the organization's LDAP connections, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteLdapConnection(ctx, dbgen.DeleteLdapConnectionParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := recordChange(ctx, tx, actor, organizationID, id, "ldap.connection_deleted", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
