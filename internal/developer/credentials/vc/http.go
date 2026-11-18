package vc

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the verifiable credential HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers organization-scoped admin endpoints (require a user JWT / API key).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/credentials", h.list)
	r.Post("/organizations/{organizationID}/credentials", h.issue)
	r.Post("/organizations/{organizationID}/credentials/{id}/revoke", h.revoke)
}

// MountPublic registers the public verify endpoint — any relying party can
// present a JWT-VC to check it (no session). CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/credentials/verify", h.verify)
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

func (h *Handler) issue(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in IssueInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.Issue(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Service.Revoke(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Credential string `json:"credential"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if strings.TrimSpace(in.Credential) == "" {
		httpx.WriteError(w, r, ErrCredentialRequired)
		return
	}
	res, err := h.Service.Verify(r.Context(), in.Credential)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
