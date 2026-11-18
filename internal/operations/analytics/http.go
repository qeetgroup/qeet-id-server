package analytics

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the dashboard endpoint.
type Handler struct {
	Reader *Reader
}

// Mount registers GET /organizations/{organizationID}/analytics/overview.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/analytics/overview", h.overview)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	from, to, asked, err := parseRange(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Reader.Overview(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if asked {
		if out.Range, err = h.Reader.Range(r.Context(), tid, from, to, r.URL.Query().Get("method")); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
