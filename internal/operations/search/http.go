package search

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler wires the search Service into the chi router.
type Handler struct {
	Service *Service
}

// Mount registers the search endpoint on the authenticated router group.
// The route is intentionally absent from the RBAC permissionMap — access to
// each resource type is gated per-type inside the Service (see typePermission).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/search", h.search)
}

// search handles GET /v1/search
//
//	?q=<query>               required; 1+ chars after trimming
//	&types=<csv>             optional; comma-separated resource types to filter
//	&cursor=<opaque>         optional; pagination token from a previous response
//	&limit=<1..50>           optional; defaults to 20, capped at 50
func (h *Handler) search(w http.ResponseWriter, r *http.Request) {
	// Tenant is derived from the authenticated principal only — never from
	// the URL or body (QID-18).
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

	// User principals get per-type RBAC checks; API-key and service-principal
	// callers (p.UserID == nil) skip them — they are already scoped to the
	// tenant by their credential.
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
