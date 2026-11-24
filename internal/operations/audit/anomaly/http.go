package anomaly

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the anomaly endpoints.
type Handler struct {
	Service *Service
}

// Mount registers the anomaly routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/audit/anomalies", h.list)
	r.Get("/organizations/{organizationID}/audit/anomalies/summary", h.summary)
	r.Post("/organizations/{organizationID}/audit/anomalies/{id}/resolve", h.resolve)
	r.Get("/organizations/{organizationID}/audit/anomaly-settings", h.getSettings)
	r.Put("/organizations/{organizationID}/audit/anomaly-settings", h.updateSettings)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != "open" && status != "resolved" {
		httpx.WriteError(w, r, ErrAuditAnomalyStatusInvalid)
		return
	}
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, next, err := h.Service.ListPage(r.Context(), organizationID, status, paging.Limit(r.URL.Query(), 50, 200), after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.Page(out, next))
}

func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Summary(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) resolve(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrAuditIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, ErrAuditResolveActorRequired)
		return
	}
	if err := h.Service.Resolve(r.Context(), organizationID, id, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getSettings(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.GetSettings(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) updateSettings(w http.ResponseWriter, r *http.Request) {
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
	out, err := h.Service.UpdateSettings(r.Context(), organizationID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
