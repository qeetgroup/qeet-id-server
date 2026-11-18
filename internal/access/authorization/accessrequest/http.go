package accessrequest

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

// Handler serves access requests: a person's own under /me, and an
// organization's under /organizations/{organizationID}, for the people who can grant roles.
type Handler struct {
	Service *Service
	// GrantCheck refuses an approval whose role would give authority the
	// approver doesn't hold (rbac.Repository.CheckGrantRole).
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID, roleID uuid.UUID) error
}

// Mount registers the routes on the authenticated /v1 router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/me/access-requests", h.listMine)
	r.Post("/me/access-requests", h.create)
	r.Get("/me/access-requests/roles", h.roles)
	r.Post("/me/access-requests/{id}/cancel", h.cancel)

	r.Get("/organizations/{organizationID}/access-requests", h.list)
	r.Get("/organizations/{organizationID}/access-requests/{id}", h.get)
	r.Post("/organizations/{organizationID}/access-requests/{id}/approve", h.approve)
	r.Post("/organizations/{organizationID}/access-requests/{id}/deny", h.deny)
}

// caller is the signed-in person and the organization they're signed in to.
func caller(r *http.Request) (organizationID, userID uuid.UUID, err error) {
	if organizationID, err = httpx.RequireOrganization(r); err != nil {
		return
	}
	userID, err = httpx.RequireUser(r)
	return
}

func pathID(r *http.Request) (uuid.UUID, error) {
	return httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
}

func (h *Handler) listMine(w http.ResponseWriter, r *http.Request) {
	tid, uid, err := caller(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListMine(r.Context(), tid, uid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_requests": out})
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, uid, err := caller(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.RoleID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("role_id is required"))
		return
	}
	out, err := h.Service.Create(r.Context(), tid, uid, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"access_request": out})
}

func (h *Handler) roles(w http.ResponseWriter, r *http.Request) {
	tid, uid, err := caller(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.RequestableRoles(r.Context(), tid, uid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"roles": out})
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	tid, uid, err := caller(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Cancel(r.Context(), tid, uid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tid, r.URL.Query().Get("status"), paging.Limit(r.URL.Query(), 100, 200))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pending, err := h.Service.PendingCount(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_requests": out, "pending": pending})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Get(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_request": out})
}

// decisionInput is an approval's optional note, or a denial's required one.
type decisionInput struct {
	Note string `json:"note"`
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	tid, uid, err := caller(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in decisionInput
	// The note is optional, so an approval may come with no body at all.
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	req, err := h.Service.Get(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Approving gives the role, so it needs what giving it directly needs.
	if h.GrantCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, req.Role.ID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Approve(r.Context(), tid, id, uid, in.Note, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_request": out})
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	tid, uid, err := caller(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in decisionInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.Deny(r.Context(), tid, id, uid, in.Note, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"access_request": out})
}
