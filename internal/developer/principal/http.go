package principal

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the service principal HTTP API.
type Handler struct {
	Service *Service
	// GrantCheck refuses a credential carrying a scope the caller doesn't hold
	// (rbac.Repository.CheckGrantScopes). Without it creating one is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, scopes []string) error
}

// Mount registers the service principal routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/service-principals", h.create)
	r.Get("/organizations/{organizationID}/service-principals", h.list)
	r.Delete("/service-principals/{id}", h.disable)
	r.Post("/organizations/{organizationID}/service-principals/{id}/rotate-secret", h.rotateSecret)
	r.Post("/organizations/{organizationID}/service-principals/{id}/enable", h.enable)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if h.GrantCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, in.Scopes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, secret, err := h.Service.Create(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"service_principal": p,
		"client_id":         p.ID,
		"client_secret":     secret,
		"warning":           "secret shown once",
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Disable(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateSecret handles POST /v1/organizations/{organizationID}/service-principals/{id}/rotate-secret.
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	tid, id, err := pathIDs(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	overlap, err := rotation.Request(r, tid, id, h.Service.Scopes, h.GrantCheck)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	secret, until, err := h.Service.RotateSecret(r.Context(), tid, id, overlap, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"client_id":                  id,
		"client_secret":              secret,
		"previous_secret_expires_at": until,
		"warning":                    "secret shown once",
	})
}

// enable handles POST /v1/organizations/{organizationID}/service-principals/{id}/enable.
func (h *Handler) enable(w http.ResponseWriter, r *http.Request) {
	tid, id, err := pathIDs(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Enable(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
