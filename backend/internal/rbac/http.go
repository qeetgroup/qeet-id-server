package rbac

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Handler struct {
	Repo     *Repository
	Validate *validator.Validate
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/permissions", h.listPermissions)

	r.Get("/tenants/{tenantID}/roles", h.listRoles)
	r.Post("/tenants/{tenantID}/roles", h.createRole)

	r.Post("/roles/{roleID}/permissions/{permID}", h.grant)
	r.Delete("/roles/{roleID}/permissions/{permID}", h.revoke)

	r.Post("/users/{userID}/tenants/{tenantID}/roles/{roleID}", h.assign)
	r.Delete("/users/{userID}/tenants/{tenantID}/roles/{roleID}", h.unassign)

	r.Get("/users/{userID}/tenants/{tenantID}/permissions", h.effective)
	r.Get("/check", h.check)
}

func (h *Handler) listPermissions(w http.ResponseWriter, r *http.Request) {
	out, err := h.Repo.ListPermissions(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) listRoles(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	out, err := h.Repo.ListRoles(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type createRoleInput struct {
	Name        string `json:"name" validate:"required,min=1,max=64"`
	Description string `json:"description" validate:"omitempty,max=500"`
}

func (h *Handler) createRole(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	var in createRoleInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail(err.Error()))
		return
	}
	role, err := h.Repo.CreateRole(r.Context(), tid, in.Name, in.Description, false)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, role)
}

func (h *Handler) grant(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	permID, err := uuid.Parse(chi.URLParam(r, "permID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid permID"))
		return
	}
	if err := h.Repo.GrantPermission(r.Context(), roleID, permID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	permID, err := uuid.Parse(chi.URLParam(r, "permID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid permID"))
		return
	}
	if err := h.Repo.RevokePermission(r.Context(), roleID, permID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) assign(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	var grantedBy *uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.UserID != nil {
		grantedBy = p.UserID
	}
	if err := h.Repo.AssignRole(r.Context(), uid, tid, rid, grantedBy); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unassign(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	if err := h.Repo.UnassignRole(r.Context(), uid, tid, rid); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) effective(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid userID"))
		return
	}
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	keys, err := h.Repo.EffectivePermissions(r.Context(), uid, tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"permissions": keys})
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uid, err := uuid.Parse(q.Get("user_id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid user_id"))
		return
	}
	tid, err := uuid.Parse(q.Get("tenant_id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenant_id"))
		return
	}
	perm := q.Get("permission")
	if perm == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("permission required"))
		return
	}
	ok, err := h.Repo.Check(r.Context(), uid, tid, perm)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"allowed": ok})
}
