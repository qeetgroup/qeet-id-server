package entitlements

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves a tenant's entitlements, so the console gates its UI on the
// same source the backend enforces.
type Handler struct {
	Service *Service
}

// Mount registers the entitlement routes. Their {tenantID} parameter makes
// EnforceTenantScope reject any tenant but the caller's own.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/entitlements", h.get)
	r.Get("/tenants/{tenantID}/entitlements/usage", h.usage)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	// EnforceTenantScope has checked that the path tenant is the caller's.
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ent, err := h.Service.Resolve(r.Context(), scope)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ent)
}

// usage returns the tenant's current consumption per resource. It is separate
// from the entitlements route, which the console reads on every page, so the
// count queries run only when needed.
func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u, err := h.Service.Usage(r.Context(), scope)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"usage": u})
}
