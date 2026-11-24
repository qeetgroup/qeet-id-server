package directory

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the directory HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the directory routes on r.
func (handler *Handler) Mount(router chi.Router) {
	router.Get("/organizations/{organizationID}/directory/connections", handler.list)
	router.Get("/organizations/{organizationID}/directory/profiles/{userID}", handler.profiles)
	router.Get("/organizations/{organizationID}/directory/activity", handler.events)
	router.Post("/organizations/{organizationID}/directory/alerts", handler.createAlert)
	router.Get("/organizations/{organizationID}/directory/alerts", handler.listAlerts)
	router.Patch("/organizations/{organizationID}/directory/alerts/{alertID}", handler.updateAlert)
	router.Delete("/organizations/{organizationID}/directory/alerts/{alertID}", handler.deleteAlert)
	router.Get("/organizations/{organizationID}/directory/errors", handler.errors)
	router.Post("/organizations/{organizationID}/directory/errors/{eventID}/resolve", handler.resolveError)
	router.Post("/organizations/{organizationID}/directory/errors/{eventID}/retry", handler.retryError)
	router.Get("/organizations/{organizationID}/directory/connections/{connectionID}/mappings", handler.mappings)
	router.Post("/organizations/{organizationID}/directory/connections/{connectionID}/mappings", handler.saveMapping)
	router.Post("/organizations/{organizationID}/directory/connections/{connectionID}/mappings/preview", handler.previewMappings)
	router.Put("/organizations/{organizationID}/directory/connections/{connectionID}/mappings/{mappingID}", handler.saveMapping)
	router.Delete("/organizations/{organizationID}/directory/connections/{connectionID}/mappings/{mappingID}", handler.deleteMapping)
}

func requireOrganization(request *http.Request) (uuid.UUID, error) {
	organizationID, err := httpx.RequireOrganization(request)
	if err != nil {
		return uuid.Nil, err
	}
	if organizationID == uuid.Nil {
		return uuid.Nil, errs.ErrUnauthorized
	}
	pathOrganization, err := httpx.PathUUID(request, "organizationID", errs.ErrBadRequest)
	if err != nil {
		return uuid.Nil, err
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
