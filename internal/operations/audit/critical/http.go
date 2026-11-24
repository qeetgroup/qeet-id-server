package critical

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves GET /v1/organizations/{organizationID}/critical-events.
type Handler struct {
	Service *Service
}

// Mount registers the route on the authenticated /v1 router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/critical-events", h.list)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	hours := defaultHours
	if v := r.URL.Query().Get("hours"); v != "" {
		if hours, err = strconv.Atoi(v); err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid hours"))
			return
		}
	}
	out, err := h.Service.List(r.Context(), tid, hours)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	body := map[string]any{"hours": hours}
	if len(out) > maxEvents {
		out = out[:maxEvents]
		body["truncated"] = true
	}
	high := 0
	for _, e := range out {
		if e.Level == High {
			high++
		}
	}
	body["events"], body["high"] = out, high
	httpx.WriteJSON(w, http.StatusOK, body)
}
