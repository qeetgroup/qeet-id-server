package entitlements

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves an organization's entitlements, so the console gates its UI on the
// same source the backend enforces, and its current usage.
type Handler struct {
	service  *Service
	consumed UsageResolver
}

// NewHandler returns a Handler serving service's entitlements and usage's
// consumption. It refuses a nil service or usage.
func NewHandler(service *Service, usage UsageResolver) (*Handler, error) {
	if service == nil || usage == nil {
		return nil, errors.New("entitlements: the handler needs the service and a usage resolver")
	}
	return &Handler{service: service, consumed: usage}, nil
}

// Service returns the service h serves, for a tool that reads plans directly,
// such as the development seed.
func (h *Handler) Service() *Service { return h.service }

// Mount registers the entitlement routes. Their {organizationID} parameter makes
// EnforceOrganizationScope reject any organization but the caller's own.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/entitlements", h.get)
	r.Get("/organizations/{organizationID}/entitlements/usage", h.usage)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	// EnforceOrganizationScope has checked that the path organization is the caller's.
	scope, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ent, err := h.service.Resolve(r.Context(), scope)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ent)
}

// usage returns the organization's current consumption per resource. It is separate
// from the entitlements route, which the console reads on every page, so the
// count queries run only when needed.
func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	scope, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u, err := h.consumed.Usage(r.Context(), scope)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"usage": u})
}
