package search

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the search endpoint.
type Handler struct {
	Service *Service
}

// Mount registers GET /search. The route admits only user principals, and the
// Service checks a read permission for each resource type.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/search", h.search)
}

// search serves GET /v1/search. q is required; types is an optional
// comma-separated list of resource types; cursor comes from a previous
// response; limit outside 1..50 becomes 20.
func (h *Handler) search(w http.ResponseWriter, r *http.Request) {
	// Tenant comes from the authenticated principal, never the URL or body.
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("q is required"))
		return
	}

	// Parse optional type filter: "user,role,group" → []string{"user","role","group"}.
	var types []string
	if raw := strings.TrimSpace(r.URL.Query().Get("types")); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			if t = strings.TrimSpace(t); t != "" {
				types = append(types, t)
			}
		}
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cursor := r.URL.Query().Get("cursor")

	// The route admits only user principals, so p.UserID is set and every type
	// is permission-checked.
	p := httpx.PrincipalFromCtx(r.Context())
	userID := p.UserID // *uuid.UUID; nil for non-user principals

	results, nextCursor, err := h.Service.Search(r.Context(), tenantID, userID, q, types, cursor, limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := map[string]any{
		"results": results,
	}
	if nextCursor != "" {
		resp["next_cursor"] = nextCursor
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
