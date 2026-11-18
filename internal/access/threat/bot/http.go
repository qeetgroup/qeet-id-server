package bot

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the bot detection HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the bot detection routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/security/bots", h.overview)
	r.Get("/organizations/{organizationID}/security/bots/settings", h.getSettings)
	r.Put("/organizations/{organizationID}/security/bots/settings", h.putSettings)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	query := r.URL.Query()
	verdict := query.Get("verdict")
	if verdict != "" && verdict != "allowed" && verdict != "challenged" && verdict != "blocked" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid verdict"))
		return
	}
	after, err := paging.ParseCursor(query)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	page, err := h.Service.List(r.Context(), organizationID, paging.Limit(query, 50, 200), after, verdict)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	stats, err := h.Service.Stats(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, Overview{Page: page, Stats: stats})
}

func (h *Handler) getSettings(w http.ResponseWriter, r *http.Request) {
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
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request) {
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
	httpx.WriteJSON(w, http.StatusOK, st)
}
