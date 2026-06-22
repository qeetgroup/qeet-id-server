package rbac

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

type Handler struct {
	Repo     *Repository
	Service  *Service
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

	r.Get("/tenants/{tenantID}/groups/{groupID}/roles", h.listGroupRoles)
	r.Post("/tenants/{tenantID}/groups/{groupID}/roles/{roleID}", h.assignGroupRole)
	r.Delete("/tenants/{tenantID}/groups/{groupID}/roles/{roleID}", h.unassignGroupRole)

	r.Get("/users/{userID}/tenants/{tenantID}/permissions", h.effective)
	r.Get("/check", h.check)
}

// actorOf captures the request's audit provenance from the principal + headers.
func actorOf(r *http.Request) audit.Actor {
	a := audit.Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		a.UserID = p.UserID
		a.Type = "user"
		if p.ActorType != "" {
			a.Type = p.ActorType
		}
	}
	return a
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
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	role, err := h.Service.CreateRole(r.Context(), tid, in.Name, in.Description, actorOf(r))
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
	if err := h.Service.GrantPermission(r.Context(), roleID, permID, actorOf(r)); err != nil {
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
	if err := h.Service.RevokePermission(r.Context(), roleID, permID, actorOf(r)); err != nil {
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
	actor := actorOf(r)
	if err := h.Service.AssignRole(r.Context(), uid, tid, rid, actor.UserID, actor); err != nil {
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
	if err := h.Service.UnassignRole(r.Context(), uid, tid, rid, actorOf(r)); err != nil {
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

// check authorizes an action. By default it returns {"allowed": bool}. With the
// opt-in query flag explain=true it returns the full Explanation (allowed, the
// grant path(s), and a reason on denial) computed by the same resolver — the
// default contract is untouched so existing callers/tests keep working.
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
	if q.Get("explain") == "true" {
		exp, err := h.Repo.Explain(r.Context(), uid, tid, perm)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, exp)
		return
	}
	ok, err := h.Repo.Check(r.Context(), uid, tid, perm)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"allowed": ok})
}

func (h *Handler) listGroupRoles(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	gid, err := uuid.Parse(chi.URLParam(r, "groupID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid groupID"))
		return
	}
	out, err := h.Repo.ListGroupRoles(r.Context(), gid, tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) assignGroupRole(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	gid, err := uuid.Parse(chi.URLParam(r, "groupID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid groupID"))
		return
	}
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	actor := actorOf(r)
	if err := h.Service.AssignRoleToGroup(r.Context(), gid, tid, rid, actor.UserID, actor); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unassignGroupRole(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	gid, err := uuid.Parse(chi.URLParam(r, "groupID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid groupID"))
		return
	}
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	if err := h.Service.RemoveRoleFromGroup(r.Context(), gid, tid, rid, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
