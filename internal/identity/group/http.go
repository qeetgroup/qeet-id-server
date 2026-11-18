package group

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the group HTTP API.
type Handler struct {
	Service *Service
	// GrantCheck refuses adding someone to a group, taking them out or deleting
	// it, when its roles carry authority the caller doesn't hold
	// (rbac.Repository.CheckGrantGroup). Without it all three are refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID, groupID uuid.UUID) error
	// ActOnCheck refuses taking someone out of a group when they outrank the
	// caller (rbac.Repository.CheckActOn). Without it removing a member is
	// refused.
	ActOnCheck func(ctx context.Context, caller *httpx.Principal, organizationID, userID uuid.UUID) error
	// ReadsRoles reports whether the caller may read roles (role.read), and so
	// sees each listed group's roles. Without it no one does.
	ReadsRoles func(r *http.Request) bool
}

// Mount registers the group routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/groups", h.create)
	r.Get("/organizations/{organizationID}/groups", h.list)
	r.Delete("/groups/{id}", h.delete)
	r.Patch("/groups/{id}", h.update)
	r.Post("/groups/{id}/members/{userID}", h.addMember)
	r.Delete("/groups/{id}/members/{userID}", h.removeMember)
	r.Get("/groups/{id}/members", h.listMembers)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = organizationID // scope from principal, never the body
	g, err := h.Service.Create(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, g)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	query := r.URL.Query()
	var role *uuid.UUID
	if raw := query.Get("role"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid role"))
			return
		}
		role = &id
	}
	grants := query.Get("grants")
	if grants != "" && grants != "some" && grants != "none" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("grants must be some or none"))
		return
	}
	readsRoles := h.ReadsRoles != nil && h.ReadsRoles(r)
	if !readsRoles && (role != nil || grants != "") {
		httpx.WriteError(w, r, errs.ErrRBACPermissionDenied.WithDetail("filtering by role needs role.read"))
		return
	}
	out, err := h.Service.List(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if readsRoles {
		if err := h.Service.WithRoles(r.Context(), organizationID, out); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		out = filterByRoles(out, role, grants)
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Deleting a group takes its roles from everyone in it, so it is held to
	// the rule for giving them.
	if err := h.grant(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	g, err := h.Service.Update(r.Context(), id, organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (h *Handler) addMember(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	uid, err := httpx.PathUUID(r, "userID", errs.ErrBadRequest.WithDetail("invalid userID"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.grant(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.AddMember(r.Context(), id, uid, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	uid, err := httpx.PathUUID(r, "userID", errs.ErrBadRequest.WithDetail("invalid userID"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Taking someone out of a group takes its roles from them: held to the rule
	// for giving them, and to their standing, as removing a role is.
	if err := h.grant(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.ActOnCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	if err := h.ActOnCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, uid); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RemoveMember(r.Context(), id, uid, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// grant refuses the caller giving or taking away group id's roles in organizationID
// when they lack what the roles carry (GrantCheck); without the check it
// refuses every caller.
func (h *Handler) grant(r *http.Request, organizationID, id uuid.UUID) error {
	if h.GrantCheck == nil {
		return errs.ErrNotImplemented
	}
	return h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, id)
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListMembers(r.Context(), id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// MountTemplates registers the template and bulk-import routes.
func (h *Handler) MountTemplates(r chi.Router) {
	r.Get("/groups/templates", h.listTemplates)
	r.Post("/groups/templates", h.createTemplate)
	r.Delete("/groups/templates/{id}", h.deleteTemplate)
	r.Post("/groups/templates/{id}/apply", h.applyTemplate)
	r.Post("/groups/import", h.importGroups)
}

func (h *Handler) listTemplates(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Service.ListTemplates(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

func (h *Handler) createTemplate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in TemplateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	t, err := h.Service.CreateTemplate(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
}

func (h *Handler) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteTemplate(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type applyTemplateInput struct {
	// Optional: graft the template under an existing group instead of at root.
	ParentID *uuid.UUID `json:"parent_id"`
	// Optional: put before every group's name, and rename the one top group.
	Prefix   string `json:"prefix"`
	RootName string `json:"root_name"`
}

func (h *Handler) applyTemplate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in applyTemplateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	created, err := h.Service.ApplyTemplate(r.Context(), id, organizationID, ApplyOptions(in), audit.ActorOf(r))
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
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in importInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.ImportGroups(r.Context(), organizationID, in.Groups, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// 200, not 201: rows are attempted independently, so a "successful" import
	// can still contain failures the caller must read.
	httpx.WriteJSON(w, http.StatusOK, res)
}
