package secret

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the secrets vault HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the secrets vault routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/secrets", h.list)
	r.Post("/organizations/{organizationID}/secrets", h.create)
	r.Patch("/organizations/{organizationID}/secrets/{id}", h.update)
	r.Post("/organizations/{organizationID}/secrets/{id}/reveal", h.reveal)
	r.Delete("/organizations/{organizationID}/secrets/{id}", h.del)
	// Token vaulting: a scoped principal (e.g. an AI agent) fetches a vault
	// secret by name. Gated by a vault:<name> (or vault:read) scope; audited.
	r.Get("/vault/{name}", h.vaultGet)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Name                 string `json:"name"`
		Scope                string `json:"scope"`
		Value                string `json:"value"`
		RotationIntervalDays *int32 `json:"rotation_interval_days"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sec, err := h.Service.Create(r.Context(), organizationID, in.Name, in.Scope, in.Value, in.RotationIntervalDays, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sec)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sec, err := h.Service.Update(r.Context(), organizationID, id, in, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sec)
}

func (h *Handler) reveal(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	_, value, err := h.Service.Reveal(r.Context(), organizationID, id, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": value})
}

// vaultGet returns a vault secret's value to a scoped principal (e.g. an AI
// agent fetching a credential at runtime). Organization comes from the caller's
// token; access requires a matching vault scope and is always audited.
func (h *Handler) vaultGet(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	name := chi.URLParam(r, "name")
	if !hasVaultScope(p.Scopes, name) {
		httpx.WriteError(w, r, ErrScopeRequired)
		return
	}
	_, value, err := h.Service.GetByName(r.Context(), organizationID, name, CallerOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"name": name, "value": value})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), organizationID, id, CallerOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
