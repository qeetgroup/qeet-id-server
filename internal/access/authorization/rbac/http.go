package rbac

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the RBAC routes. Decider answers GET /v1/check across every
// engine, so an attribute (ABAC) deny refuses there as everywhere else.
type Handler struct {
	Repo     *Repository
	Service  *Service
	Validate *validator.Validate
	Decider  *decide.Decider
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/permissions", h.listPermissions)

	r.Get("/tenants/{tenantID}/roles", h.listRoles)
	r.Post("/tenants/{tenantID}/roles", h.createRole)

	r.Get("/roles/{roleID}/permissions", h.listRolePermissions)
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

// requirePathTenant returns the path's {tenantID} if it is the caller's own
// tenant and 403 otherwise, so an admin can't reach another tenant's roles and
// assignments by editing the URL.
func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

// scopedRole returns the path's {roleID} if the role belongs to the caller's
// tenant. These routes carry no tenant, so another tenant's role is
// ErrNotFound, the same as a missing one, and role IDs can't be probed.
func (h *Handler) scopedRole(r *http.Request) (uuid.UUID, error) {
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid roleID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	owner, err := h.Repo.RoleTenant(r.Context(), roleID)
	if err != nil {
		return uuid.Nil, err
	}
	if owner != scope {
		return uuid.Nil, errs.ErrNotFound
	}
	return roleID, nil
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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

func (h *Handler) listRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := h.scopedRole(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Repo.ListRolePermissions(r.Context(), roleID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) grant(w http.ResponseWriter, r *http.Request) {
	roleID, err := h.scopedRole(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	permID, err := uuid.Parse(chi.URLParam(r, "permID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid permID"))
		return
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.CheckGrantPermission(r.Context(), httpx.PrincipalFromCtx(r.Context()), scope, permID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.GrantPermission(r.Context(), roleID, permID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	roleID, err := h.scopedRole(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	if err := h.Repo.CheckGrantRole(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, rid); err != nil {
		httpx.WriteError(w, r, err)
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	keys, err := h.Repo.EffectivePermissions(r.Context(), uid, tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"permissions": keys})
}

// check answers GET /v1/check with the composed decision (decide.Decider):
// {"allowed", "decided_by": {"model", "rule"}}, ABAC detail shown only to a
// caller who may read policies. explain=true adds the role grant paths, a
// reason on denial and the decision's trace.
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
	// tenant_id comes from the query, so it must be the caller's own tenant, or
	// /check would be a cross-tenant permission oracle.
	if scope, serr := httpx.RequireTenant(r); serr != nil {
		httpx.WriteError(w, r, serr)
		return
	} else if tid != scope {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant mismatch"))
		return
	}
	perm := q.Get("permission")
	if perm == "" {
		httpx.WriteError(w, r, errs.ErrRBACPermissionRequired)
		return
	}
	dec, err := h.Decider.Permission(r.Context(), tid, uid, perm)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	dec = h.Decider.ForViewer(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, dec)
	out := map[string]any{"allowed": dec.Allow, "decided_by": dec.DecidedBy()}
	if q.Get("explain") == "true" {
		exp, err := h.Repo.Explain(r.Context(), uid, tid, perm)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		out["paths"] = exp.Paths
		if !dec.Allow {
			out["reason"] = exp.Reason
			if dec.Model == decide.ModelABAC {
				out["reason"] = "refused by " + dec.Rule
			}
		}
		out["trace"] = dec.Trace
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) listGroupRoles(w http.ResponseWriter, r *http.Request) {
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
	if err := h.Repo.CheckGrantRole(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, rid); err != nil {
		httpx.WriteError(w, r, err)
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
	tid, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
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
