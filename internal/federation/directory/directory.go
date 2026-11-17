// Package directory gives administrators one view of an organization's directory
// connections (its SCIM endpoint and LDAP connections): sync activity and
// errors, failure alerts, and the attribute mappings applied to the profiles
// they provision.
package directory

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
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

// Service gives one view of an organization's directory connections, their events
// and their mappings.
type Service struct {
	scim SCIMSource
	ldap LDAPSource
	pool *pgxpool.Pool
}

// NewService returns the directory service.
func NewService(scimSource SCIMSource, ldapSource LDAPSource) *Service {
	return &Service{scim: scimSource, ldap: ldapSource}
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
			Type: "ldap", Status: source.Status, Health: "unknown", Scope: "users-on-signin",
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
	if service.pool == nil {
		return nil
	}
	people := map[string]int{}
	rows, err := service.pool.Query(ctx, `
		SELECT ei.connection_id::text, count(DISTINCT ei.user_id)::int
		FROM account.external_identities ei
		JOIN account.users u ON u.id = ei.user_id AND u.deleted_at IS NULL
		WHERE ei.organization_id = $1 AND ei.provider = 'ldap' AND ei.connection_id IS NOT NULL
		GROUP BY ei.connection_id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return err
		}
		people[id] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var groups int
	if err := service.pool.QueryRow(ctx, `SELECT count(*)::int FROM organization.groups WHERE organization_id = $1 AND provisioned_via = 'scim'`, organizationID).Scan(&groups); err != nil {
		return err
	}
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

// Handler serves the directory HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the directory routes on r.
func (handler *Handler) Mount(router chi.Router) {
	router.Get("/tenants/{tenantID}/directory/connections", handler.list)
	router.Get("/tenants/{tenantID}/directory/profiles/{userID}", handler.profiles)
	router.Get("/tenants/{tenantID}/directory/activity", handler.events)
	router.Post("/tenants/{tenantID}/directory/alerts", handler.createAlert)
	router.Get("/tenants/{tenantID}/directory/alerts", handler.listAlerts)
	router.Patch("/tenants/{tenantID}/directory/alerts/{alertID}", handler.updateAlert)
	router.Delete("/tenants/{tenantID}/directory/alerts/{alertID}", handler.deleteAlert)
	router.Get("/tenants/{tenantID}/directory/errors", handler.errors)
	router.Post("/tenants/{tenantID}/directory/errors/{eventID}/resolve", handler.resolveError)
	router.Post("/tenants/{tenantID}/directory/errors/{eventID}/retry", handler.retryError)
	router.Get("/tenants/{tenantID}/directory/connections/{connectionID}/mappings", handler.mappings)
	router.Post("/tenants/{tenantID}/directory/connections/{connectionID}/mappings", handler.saveMapping)
	router.Post("/tenants/{tenantID}/directory/connections/{connectionID}/mappings/preview", handler.previewMappings)
	router.Put("/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}", handler.saveMapping)
	router.Delete("/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}", handler.deleteMapping)
}

func requireOrganization(request *http.Request) (uuid.UUID, error) {
	organizationID, err := httpx.RequireOrganization(request)
	if err != nil {
		return uuid.Nil, err
	}
	if organizationID == uuid.Nil {
		return uuid.Nil, errs.ErrUnauthorized
	}
	pathOrganization, err := uuid.Parse(chi.URLParam(request, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest
	}
	if pathOrganization != organizationID {
		return uuid.Nil, errs.ErrForbidden
	}
	return organizationID, nil
}

func (handler *Handler) list(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	records, err := handler.Service.List(request.Context(), organizationID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, paging.List(records))
}
