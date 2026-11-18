package risk

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler exposes risk settings over HTTP.
type Handler struct{ Service *Service }

// Mount registers the risk setting routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/security/risk-settings", h.get)
	r.Put("/organizations/{organizationID}/security/risk-settings", h.put)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.GetSettings(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, withCountrySignal(st))
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.UpdateSettings(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, withCountrySignal(st))
}
