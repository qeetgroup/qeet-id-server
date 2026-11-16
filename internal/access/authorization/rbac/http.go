package rbac

import (
	"bytes"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decisionlog"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the RBAC routes. Decider answers GET /v1/check across every
// engine, so an attribute (ABAC) deny refuses there as everywhere else.
type Handler struct {
	Repo     *Repository
	Service  *Service
	Validate *validator.Validate
	Decider  *decide.Decider
	// Decisions keeps the decisions /check answers (nil: none).
	Decisions *decisionlog.Log
}

// Mount registers the role and permission routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/permissions", h.listPermissions)

	r.Get("/tenants/{tenantID}/roles", h.listRoles)
	r.Get("/tenants/{tenantID}/roles/{roleID}/holders", h.holders)
	r.Post("/tenants/{tenantID}/roles", h.createRole)
	r.Patch("/tenants/{tenantID}/roles/{roleID}", h.updateRole)
	r.Delete("/tenants/{tenantID}/roles/{roleID}", h.deleteRole)
	r.Put("/tenants/{tenantID}/roles/{roleID}/permissions", h.setPermissions)

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

func (h *Handler) listPermissions(w http.ResponseWriter, r *http.Request) {
	out, err := h.Repo.ListPermissions(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// holders serves GET /tenants/{tenantID}/roles/{roleID}/holders: a page of
// the people holding the role (directly or through which groups) and every
// group granted it. limit is 1–500 (default 100); cursor is the next page's.
func (h *Handler) holders(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	roleID, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	if owner, err := h.Repo.RoleTenant(r.Context(), roleID); err != nil || owner != tid {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	limit, offset := 100, 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if limit, err = strconv.Atoi(raw); err != nil || limit < 1 || limit > 500 {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("limit must be 1 to 500"))
			return
		}
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if offset, err = strconv.Atoi(raw); err != nil || offset < 0 || offset > 1_000_000 {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid cursor"))
			return
		}
	}
	out, err := h.Repo.Holders(r.Context(), tid, roleID, offset, limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) listRoles(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Repo.ListRoles(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.WithHolderCounts(r.Context(), tid, out); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

type createRoleInput struct {
	Name        string `json:"name" validate:"required,min=1,max=64"`
	Description string `json:"description" validate:"omitempty,max=500"`
}

func (h *Handler) createRole(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenant(r)
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
	role, err := h.Service.CreateRole(r.Context(), tid, in.Name, in.Description, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, role)
}

type updateRoleInput struct {
	Name        *string `json:"name" validate:"omitempty,min=1,max=64"`
	Description *string `json:"description" validate:"omitempty,max=500"`
}

// updateRole serves PATCH /tenants/{tenantID}/roles/{roleID}: rename a custom
// role or change its description.
func (h *Handler) updateRole(w http.ResponseWriter, r *http.Request) {
	tid, roleID, err := pathRole(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in updateRoleInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	role, err := h.Service.UpdateRole(r.Context(), tid, roleID, in.Name, in.Description, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, role)
}

// deleteRole serves DELETE /tenants/{tenantID}/roles/{roleID}.
func (h *Handler) deleteRole(w http.ResponseWriter, r *http.Request) {
	tid, roleID, err := pathRole(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeleteRole(r.Context(), tid, roleID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pathRole is the path's tenant and {roleID}.
func pathRole(r *http.Request) (tenantID, roleID uuid.UUID, err error) {
	if tenantID, err = httpx.PathTenant(r); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	if roleID, err = uuid.Parse(chi.URLParam(r, "roleID")); err != nil {
		return uuid.Nil, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid roleID")
	}
	return tenantID, roleID, nil
}

type setPermissionsInput struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"max=500"`
}

// setPermissions serves PUT /tenants/{tenantID}/roles/{roleID}/permissions:
// the role's whole set of permissions in one change.
func (h *Handler) setPermissions(w http.ResponseWriter, r *http.Request) {
	scope, roleID, err := pathRole(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in setPermissionsInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.PermissionIDs == nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("permission_ids is required; send [] for none"))
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	slices.SortFunc(in.PermissionIDs, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	ids := slices.Compact(in.PermissionIDs)
	mayGrant, err := h.Repo.Grantable(r.Context(), httpx.PrincipalFromCtx(r.Context()), scope)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.SetPermissions(r.Context(), scope, roleID, ids, mayGrant, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
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
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
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
	if err := h.Repo.CheckRoleEditable(r.Context(), scope, roleID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.CheckGrantPermission(r.Context(), httpx.PrincipalFromCtx(r.Context()), scope, permID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.GrantPermission(r.Context(), scope, roleID, permID, audit.ActorOf(r)); err != nil {
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
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Taking a permission away is held to the rule for giving it: a built-in
	// role keeps its permissions, and nobody removes one they don't hold.
	if err := h.Repo.CheckRoleEditable(r.Context(), scope, roleID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.CheckGrantPermission(r.Context(), httpx.PrincipalFromCtx(r.Context()), scope, permID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RevokePermission(r.Context(), scope, roleID, permID, audit.ActorOf(r)); err != nil {
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
	tid, err := httpx.PathTenant(r)
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
	actor := audit.ActorOf(r)
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
	tid, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rid, err := uuid.Parse(chi.URLParam(r, "roleID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid roleID"))
		return
	}
	// Removing a role is held to the rule for giving it, and to the person's
	// standing: nobody strips someone who outranks them.
	caller := httpx.PrincipalFromCtx(r.Context())
	if err := h.Repo.CheckActOn(r.Context(), caller, tid, uid); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Repo.CheckGrantRole(r.Context(), caller, tid, rid); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.UnassignRole(r.Context(), uid, tid, rid, audit.ActorOf(r)); err != nil {
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
	tid, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	keys, err := h.Repo.EffectivePermissions(r.Context(), uid, tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	grants, err := h.Repo.Grants(r.Context(), uid, tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"permissions": keys, "grants": grants})
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
	h.Decisions.Record(r.Context(), decisionlog.Entry{TenantID: tid, Source: decisionlog.SourceCheck, Subject: uid.String(),
		Resource: "permission", Action: perm, Allowed: dec.Allow, Model: dec.Model, Rule: dec.Rule, ReasonCode: dec.ReasonCode})
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
			out["reason"], out["reason_code"] = exp.Reason, exp.ReasonCode
			if dec.Model == decide.ModelABAC {
				out["reason"], out["reason_code"] = "refused by "+dec.Rule, dec.ReasonCode
				if dec.ReasonParams != nil {
					out["reason_params"] = dec.ReasonParams
				}
			}
		}
		out["trace"] = dec.Trace
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) listGroupRoles(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenant(r)
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
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) assignGroupRole(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenant(r)
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
	actor := audit.ActorOf(r)
	if err := h.Service.AssignRoleToGroup(r.Context(), gid, tid, rid, actor.UserID, actor); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) unassignGroupRole(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenant(r)
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
	if err := h.Service.RemoveRoleFromGroup(r.Context(), gid, tid, rid, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
