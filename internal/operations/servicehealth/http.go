package servicehealth

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the service-health endpoint.
type Handler struct {
	Service *Service
}

// Mount registers GET /organizations/{organizationID}/service-health.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/service-health", h.report)
}

func (h *Handler) report(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Report(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
