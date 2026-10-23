// Package directory gives administrators one view of a tenant's directory
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

// SCIMSource lists a tenant's SCIM connection.
type SCIMSource interface {
	Config(context.Context, uuid.UUID) (*scim.ConfigView, error)
}

// LDAPSource lists a tenant's LDAP connections.
type LDAPSource interface {
	List(context.Context, uuid.UUID) ([]ldap.Connection, error)
}

// Service gives one view of a tenant's directory connections, their events
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

// List returns the tenant's connections.
func (service *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	if tenantID == uuid.Nil {
		return nil, errs.ErrUnauthorized
	}
	config, err := service.scim.Config(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errs.ErrInternalServer
	}
	ldapConnections, err := service.ldap.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	records := make([]Connection, 0, len(ldapConnections)+1)
	if config.TokenSet {
		count := config.ProvisionedCount
		records = append(records, Connection{
			ID: "scim:" + tenantID.String(), Name: "SCIM", Reference: "/scim/v2",
			Type: "scim", Status: "configured", Health: "unknown", Scope: "users-and-groups",
			CreatedAt: config.CreatedAt, LastActivityAt: config.LastUsedAt, UserCount: &count,
		})
	}
	for _, source := range ldapConnections {
		if source.TenantID != tenantID {
			return nil, errs.ErrInternalServer
		}
		records = append(records, Connection{
			ID: source.ID.String(), Name: source.Name, Reference: source.ID.String(),
			Type: "ldap", Status: source.Status, Health: "unknown", Scope: "users-on-signin",
			CreatedAt: &source.CreatedAt, LastActivityAt: source.LastLoginAt, ServerURL: &source.ServerURL,
		})
	}
	if err := service.enrichConnections(ctx, tenantID, records); err != nil {
		return nil, err
	}
	return records, nil
}

// Handler serves the directory HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the directory routes on r.
func (handler *Handler) Mount(router chi.Router) {
	router.Get("/tenants/{tenantID}/directory/connections", handler.list)
	router.Get("/tenants/{tenantID}/directory/activity", handler.events)
	router.Post("/tenants/{tenantID}/directory/alerts", handler.createAlert)
	router.Get("/tenants/{tenantID}/directory/errors", handler.errors)
	router.Post("/tenants/{tenantID}/directory/errors/{eventID}/resolve", handler.resolveError)
	router.Post("/tenants/{tenantID}/directory/errors/{eventID}/retry", handler.retryError)
	router.Get("/tenants/{tenantID}/directory/connections/{connectionID}/mappings", handler.mappings)
	router.Post("/tenants/{tenantID}/directory/connections/{connectionID}/mappings", handler.saveMapping)
	router.Post("/tenants/{tenantID}/directory/connections/{connectionID}/mappings/preview", handler.previewMappings)
	router.Put("/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}", handler.saveMapping)
	router.Delete("/tenants/{tenantID}/directory/connections/{connectionID}/mappings/{mappingID}", handler.deleteMapping)
}

func requireTenant(request *http.Request) (uuid.UUID, error) {
	tenantID, err := httpx.RequireTenant(request)
	if err != nil {
		return uuid.Nil, err
	}
	if tenantID == uuid.Nil {
		return uuid.Nil, errs.ErrUnauthorized
	}
	pathTenant, err := uuid.Parse(chi.URLParam(request, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest
	}
	if pathTenant != tenantID {
		return uuid.Nil, errs.ErrForbidden
	}
	return tenantID, nil
}

func (handler *Handler) list(response http.ResponseWriter, request *http.Request) {
	tenantID, err := requireTenant(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	records, err := handler.Service.List(request.Context(), tenantID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, map[string]any{"items": records})
}
