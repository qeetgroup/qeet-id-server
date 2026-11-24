package branding

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the branding HTTP API.
type Handler struct {
	Repo *Repository
}

// Mount registers the branding routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/branding", h.get)
	r.Put("/organizations/{organizationID}/branding", h.put)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	b, err := h.Repo.Get(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, b)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in, err := decodeBranding(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if err := h.Repo.Save(r.Context(), in, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, in)
}

// MountPublic registers the route that needs no credential: an organization's
// uploaded logo, which its emails and hosted pages link to.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/branding/{organizationID}/logo", h.logo)
}
