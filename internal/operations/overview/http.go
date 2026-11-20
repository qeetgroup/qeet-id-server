package overview

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the overview endpoint.
type Handler struct {
	Service *Service
}

// Mount registers GET /organizations/{organizationID}/overview.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/overview", h.overview)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Overview(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
