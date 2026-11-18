package decisionlog

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the decision log.
type Handler struct {
	Log *Log
}

// Mount registers GET /organizations/{organizationID}/authorization/decisions.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/authorization/decisions", h.list)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	after, err := paging.ParseCursor(q)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	f := Filter{Subject: q.Get("subject"), Source: q.Get("source"), After: after, Limit: paging.Limit(q, 50, 200)}
	f.Days, _ = strconv.Atoi(q.Get("days"))
	if a := q.Get("allowed"); a != "" {
		allowed, err := strconv.ParseBool(a)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid allowed"))
			return
		}
		f.Allowed = &allowed
	}
	out, err := h.Log.List(r.Context(), organizationID, f)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
