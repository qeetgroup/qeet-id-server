package domainverify

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the domain verification HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the domain verification routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/domains", h.list)
	r.Post("/organizations/{organizationID}/domains", h.add)
	r.Post("/organizations/{organizationID}/domains/{id}/verify", h.verify)
	r.Get("/organizations/{organizationID}/login-domain", h.loginDomain)
	r.Post("/organizations/{organizationID}/login-domain/check", h.checkLoginDomain)
	r.Patch("/organizations/{organizationID}/domains/{id}", h.updateSettings)
	r.Delete("/organizations/{organizationID}/domains/{id}", h.remove)
	r.Get("/organizations/{organizationID}/break-glass-members", h.listBreakGlass)
	r.Put("/organizations/{organizationID}/break-glass-members/{userID}", h.addBreakGlass)
	r.Delete("/organizations/{organizationID}/break-glass-members/{userID}", h.removeBreakGlass)
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

type addInput struct {
	Domain string `json:"domain"`
}

func (h *Handler) add(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in addInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Service.Add(r.Context(), organizationID, in.Domain, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, d)
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
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
	d, err := h.Service.Verify(r.Context(), id, organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (h *Handler) remove(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Service.Remove(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type updateSettingsInput struct {
	SSOEnabled *bool `json:"sso_enabled"`
	JITEnabled *bool `json:"jit_enabled"`
}

func (h *Handler) updateSettings(w http.ResponseWriter, r *http.Request) {
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
	var in updateSettingsInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Service.UpdateSettings(r.Context(), id, organizationID, in.SSOEnabled, in.JITEnabled, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// MountPublic registers POST /sso/discovery, which needs no credential.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/sso/discovery", h.discover)
}
