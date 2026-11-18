package adminportal

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func (h *Handler) scimConfig(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySCIM)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.SCIM.Config(r.Context(), l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) scimRotate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySCIM)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	_, full, err := h.SCIM.Rotate(ctx, l.OrganizationID, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.SCIM.Config(ctx, l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"token": full, "config": cfg})
}

func (h *Handler) scimRevoke(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySCIM)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.SCIM.Revoke(r.Context(), l.OrganizationID, portalActor(l, r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
