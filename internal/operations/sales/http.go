package sales

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler exposes the contact-sales endpoint.
type Handler struct {
	Service *Service
}

// Mount registers POST /sales/leads.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/sales/leads", h.submit)
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	var in Lead
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var organizationID, userID *uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		organizationID, userID = p.OrganizationID, p.UserID
	}
	if err := h.Service.Submit(r.Context(), organizationID, userID, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "received"})
}
