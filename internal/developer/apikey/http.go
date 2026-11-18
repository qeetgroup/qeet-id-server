package apikey

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the API key HTTP API.
type Handler struct {
	Service *Service
	// GrantCheck refuses a credential carrying a scope the caller doesn't hold
	// (rbac.Repository.CheckGrantScopes). Without it creating one is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, scopes []string) error
}

// Mount registers the API key routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/api-keys", h.create)
	r.Get("/organizations/{organizationID}/api-keys", h.list)
	r.Delete("/api-keys/{id}", h.revoke)
	r.Post("/organizations/{organizationID}/api-keys/{id}/rotate", h.rotate)
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
	in.Actor = audit.ActorOf(r)
	if h.GrantCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, in.Scopes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	k, raw, err := h.Service.Create(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"api_key": k,
		"secret":  raw,
		"warning": "This secret is only shown once. Store it now.",
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

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Revoke(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotate handles POST /v1/organizations/{organizationID}/api-keys/{id}/rotate.
func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	overlap, err := rotation.Request(r, tid, id, h.Service.Scopes, h.GrantCheck)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	k, raw, err := h.Service.Rotate(r.Context(), tid, id, overlap, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"api_key": k,
		"secret":  raw,
		"warning": "This secret is only shown once. Store it now. The old key stops at the end of the overlap.",
	})
}
