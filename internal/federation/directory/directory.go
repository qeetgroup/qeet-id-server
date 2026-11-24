// Package directory gives administrators one view of an organization's directory
// connections (its SCIM endpoint and LDAP connections): sync activity and
// errors, failure alerts, and the attribute mappings applied to the profiles
// they provision.
package directory

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/directory/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Connection is a SCIM or LDAP directory connection, as listed.
type Connection struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Reference      string     `json:"reference"`
	Type           string     `json:"type"`
	Status         string     `json:"status"`
	Health         string     `json:"health"`
	Environment    *string    `json:"environment"`
	Scope          string     `json:"scope"`
	CreatedAt      *time.Time `json:"created_at"`
	LastActivityAt *time.Time `json:"last_activity_at"`
	LastSyncAt     *time.Time `json:"last_sync_at"`
	UserCount      *int       `json:"user_count"`
	GroupCount     *int       `json:"group_count"`
	ServerURL      *string    `json:"server_url"`
}

// SCIMSource lists an organization's SCIM connection.
type SCIMSource interface {
	Config(context.Context, uuid.UUID) (*scim.ConfigView, error)
}

// LDAPSource lists an organization's LDAP connections.
type LDAPSource interface {
	List(context.Context, uuid.UUID) ([]ldap.Connection, error)
}

// Store records the connections' events and keeps their attribute mappings:
// the part SCIM and LDAP report to and map through, so it is built before them.
type Store struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewStore returns the store on pool.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("directory: missing pool")
	}
	return &Store{pool: pool, q: dbgen.New(pool)}, nil
}

// Service gives one view of an organization's directory connections, their events
// and their mappings.
type Service struct {
	*Store
	scim SCIMSource
	ldap LDAPSource
}

// NewService returns the directory service over store and the two sources.
func NewService(store *Store, scimSource SCIMSource, ldapSource LDAPSource) (*Service, error) {
	switch {
	case store == nil:
		return nil, errors.New("directory: missing store")
	case scimSource == nil:
		return nil, errors.New("directory: missing SCIM source")
	case ldapSource == nil:
		return nil, errors.New("directory: missing LDAP source")
	}
	return &Service{Store: store, scim: scimSource, ldap: ldapSource}, nil
}

// List returns the organization's connections.
func (service *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Connection, error) {
	if organizationID == uuid.Nil {
		return nil, errs.ErrUnauthorized
	}
	config, err := service.scim.Config(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errs.ErrInternalServer
	}
	ldapConnections, err := service.ldap.List(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	records := make([]Connection, 0, len(ldapConnections)+1)
	if config.TokenSet {
		count := config.ProvisionedCount
		records = append(records, Connection{
			ID: "scim:" + organizationID.String(), Name: "SCIM", Reference: "/scim/v2",
			Type: "scim", Status: "configured", Health: "unknown", Scope: "users-and-groups",
			CreatedAt: config.CreatedAt, LastActivityAt: config.LastUsedAt, UserCount: &count,
		})
	}
	for _, source := range ldapConnections {
		if source.OrganizationID != organizationID {
			return nil, errs.ErrInternalServer
		}
		records = append(records, Connection{
			ID: source.ID.String(), Name: source.Name, Reference: source.ID.String(),
			Type: "ldap", Status: source.Status, Health: "unknown", Scope: "users-and-groups",
			CreatedAt: &source.CreatedAt, LastActivityAt: source.LastLoginAt, ServerURL: &source.ServerURL,
		})
	}
	if err := service.enrichConnections(ctx, organizationID, records); err != nil {
		return nil, err
	}
	if err := service.countConnections(ctx, organizationID, records); err != nil {
		return nil, err
	}
	return records, nil
}

// countConnections sets each LDAP connection's user count, the people with an
// identity it signed in, and SCIM's group count, the groups it provisioned.
func (service *Service) countConnections(ctx context.Context, organizationID uuid.UUID, records []Connection) error {
	counted, err := service.q.CountLDAPPeople(ctx, organizationID)
	if err != nil {
		return err
	}
	people := make(map[string]int, len(counted))
	for _, c := range counted {
		people[c.ConnectionID] = int(c.People)
	}
	scimGroups, err := service.q.CountSCIMGroups(ctx, organizationID)
	if err != nil {
		return err
	}
	groups := int(scimGroups)
	for i := range records {
		switch records[i].Type {
		case "ldap":
			n := people[records[i].ID]
			records[i].UserCount = &n
		case "scim":
			g := groups
			records[i].GroupCount = &g
		}
	}
	return nil
}

func (service *Service) enrichConnections(ctx context.Context, organizationID uuid.UUID, records []Connection) error {
	syncs, err := service.q.LastDirectorySyncs(ctx, organizationID)
	if err != nil {
		return err
	}
	synced := make(map[string]time.Time, len(syncs))
	for _, s := range syncs {
		synced[s.ConnectionID] = s.SyncedAt
	}
	latest, err := service.q.LatestDirectoryEvents(ctx, organizationID)
	if err != nil {
		return err
	}
	for _, event := range latest {
		var successful *time.Time
		if at, ok := synced[event.ConnectionID]; ok {
			successful = &at
		}
		for index := range records {
			if records[index].ID != event.ConnectionID {
				continue
			}
			records[index].Health = event.Status
			if event.Status == "success" {
				records[index].Health = "healthy"
			}
			if time.Since(event.StartedAt) > 24*time.Hour {
				records[index].Health = "unknown"
			}
			records[index].LastSyncAt = successful
		}
	}
	return nil
}
