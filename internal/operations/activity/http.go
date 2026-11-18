package activity

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the organization-scoped Live Activity endpoints: the SSE stream,
// history, summary and related events.
type Handler struct {
	Hub  *Hub
	pool *pgxpool.Pool
	// Access decides again, while a stream is open, whether its reader may
	// still read it, as the request was admitted: their session or credential
	// still live and audit.read still theirs. A stream it refuses, or can't
	// ask, ends. nil leaves an open stream unchecked.
	Access func(ctx context.Context, p *httpx.Principal) (bool, error)
	// RecheckEvery is how often Access is asked; 0 means streamRecheck.
	RecheckEvery time.Duration
}

// NewHandler returns a Handler that reads history from pool and live events
// from hub.
func NewHandler(pool *pgxpool.Pool, hub *Hub) *Handler {
	return &Handler{pool: pool, Hub: hub}
}

// Mount registers the activity routes. Every route requires the audit.read
// permission.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/activity", h.history)
	r.Get("/activity/summary", h.summary)
	r.Get("/activity/stream", h.stream)
	r.Get("/activity/{id}/related", h.related)
	r.Get("/organizations/{organizationID}/activity/{id}", h.event)
}

// requireOrganizationUser returns the organization and user of the authenticated principal.
// If either is missing it writes the error response and returns ok=false.
func (h *Handler) requireOrganizationUser(w http.ResponseWriter, r *http.Request) (organizationID uuid.UUID, userID uuid.UUID, ok bool) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	return organizationID, userID, true
}
