package authhook

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the login hook HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the login hook routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/auth-hooks", h.list)
	r.Post("/organizations/{organizationID}/auth-hooks", h.create)
	r.Patch("/organizations/{organizationID}/auth-hooks/{id}", h.patch)
	r.Post("/organizations/{organizationID}/auth-hooks/{id}/test", h.test)
	r.Delete("/organizations/{organizationID}/auth-hooks/{id}", h.del)
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
		URL      string `json:"url"`
		Secret   string `json:"secret"`
		FailOpen *bool  `json:"fail_open"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	failOpen := true
	if in.FailOpen != nil {
		failOpen = *in.FailOpen
	}
	hook, err := h.Service.Create(r.Context(), organizationID, in.URL, in.Secret, failOpen, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, hook)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in HookSettings
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	enabled, failOpen, err := h.Service.Update(r.Context(), id, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "fail_open": failOpen})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// test handles POST /v1/organizations/{organizationID}/auth-hooks/{id}/test.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Test(r.Context(), id, organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
