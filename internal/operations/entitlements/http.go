package entitlements

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler exposes a tenant's resolved entitlements so the console can gate the UI
// off the same source of truth the backend enforces on.
type Handler struct {
	Service *Service
}

// Mount registers GET /v1/tenants/{tenantID}/entitlements. The {tenantID} path
// param makes EnforceTenantScope fire (rejecting any tenant that isn't the
// caller's own), and the route is deliberately left unmapped in permissions.go
// so any authenticated member can read their own tenant's entitlements.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/entitlements", h.get)
	r.Get("/tenants/{tenantID}/entitlements/usage", h.usage)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	// EnforceTenantScope guarantees the path tenant equals the caller's scope, so
	// the authenticated scope is the tenant to resolve.
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

// usage returns the tenant's current consumption per resource, for the billing
// usage-vs-limits display. Kept separate from GET /entitlements (which is read
// on every page for gating) so the count queries only run when actually needed.
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
