package group

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// MountTemplates registers the template and bulk-import routes.
func (h *Handler) MountTemplates(r chi.Router) {
	r.Get("/groups/templates", h.listTemplates)
	r.Post("/groups/templates", h.createTemplate)
	r.Delete("/groups/templates/{id}", h.deleteTemplate)
	r.Post("/groups/templates/{id}/apply", h.applyTemplate)
	r.Post("/groups/import", h.importGroups)
}

func (h *Handler) listTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Service.ListTemplates(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Handler) createTemplate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in TemplateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	t, err := h.Service.CreateTemplate(r.Context(), tenantID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (h *Handler) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.DeleteTemplate(r.Context(), id, tenantID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type applyTemplateInput struct {
	// Optional: graft the template under an existing group instead of at root.
	ParentID *uuid.UUID `json:"parent_id"`
}

func (h *Handler) applyTemplate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in applyTemplateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	created, err := h.Service.ApplyTemplate(r.Context(), id, tenantID, in.ParentID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"items": created})
}

type importInput struct {
	Groups []ImportRow `json:"groups"`
}

func (h *Handler) importGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in importInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.ImportGroups(r.Context(), tenantID, in.Groups, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 200, not 201: rows are attempted independently, so a "successful" import
	// can still contain failures the caller must read.
	httpx.WriteJSON(w, http.StatusOK, res)
}
