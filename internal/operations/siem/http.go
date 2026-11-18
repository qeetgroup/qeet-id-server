package siem

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the log-sink endpoints.
type Handler struct {
	Service *Service
}

// Mount registers the log-sink routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/log-sinks", h.list)
	r.Post("/organizations/{organizationID}/log-sinks", h.create)
	r.Patch("/organizations/{organizationID}/log-sinks/{id}", h.patch)
	r.Delete("/organizations/{organizationID}/log-sinks/{id}", h.del)
	r.Post("/organizations/{organizationID}/log-sinks/test", h.testUnsaved)
	r.Post("/organizations/{organizationID}/log-sinks/{id}/test", h.testSaved)
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
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sk, err := h.Service.Create(r.Context(), organizationID, in.Type, in.Endpoint, in.Token, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sk)
}

// testUnsaved serves POST /organizations/{organizationID}/log-sinks/test: one test event
// to the destination in the body, which isn't saved.
func (h *Handler) testUnsaved(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Test(r.Context(), organizationID, in.Type, in.Endpoint, in.Token, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// testSaved serves POST /organizations/{organizationID}/log-sinks/{id}/test: one test
// event to a saved destination.
func (h *Handler) testSaved(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.TestSaved(r.Context(), organizationID, id, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.SetEnabled(r.Context(), id, organizationID, in.Enabled, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"enabled": in.Enabled})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
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
