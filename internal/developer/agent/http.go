package agent

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the agent HTTP API.
type Handler struct {
	Service *Service
	// GrantCheck refuses a credential carrying a scope the caller doesn't hold
	// (rbac.Repository.CheckGrantScopes). Without it creating one is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, scopes []string) error
}

// Mount registers organization-scoped admin endpoints (require a user JWT/API key).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/agents", h.list)
	r.Post("/organizations/{organizationID}/agents", h.create)
	r.Post("/organizations/{organizationID}/agents/kill-all", h.killAll)
	r.Post("/organizations/{organizationID}/agents/resume-all", h.resumeAll)
	r.Post("/organizations/{organizationID}/agents/{id}/rotate-secret", h.rotateSecret)
	r.Delete("/organizations/{organizationID}/agents/{id}", h.del)
	r.Patch("/organizations/{organizationID}/agents/{id}", h.patch)
	r.Post("/organizations/{organizationID}/agents/{id}/suspend", h.suspend)
	r.Post("/organizations/{organizationID}/agents/{id}/resume", h.resume)
	r.Post("/organizations/{organizationID}/agents/{id}/decommission", h.decommission)
	r.Get("/organizations/{organizationID}/agents/sponsored-by/{userID}", h.sponsoredBy)
	r.Post("/organizations/{organizationID}/agents/sponsored-by/{userID}/transfer", h.transferSponsor)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Name            string    `json:"name"`
		Scopes          []string  `json:"scopes"`
		TokenTTLSeconds int       `json:"token_ttl_seconds"`
		SponsorUserID   uuid.UUID `json:"sponsor_user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.GrantCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, in.Scopes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	a, err := h.Service.Create(r.Context(), organizationID, in.Name, in.Scopes, in.TokenTTLSeconds, in.SponsorUserID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a)
}

func (h *Handler) sponsoredBy(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	userID, err := httpx.PathUUID(r, "userID", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.AgentsSponsoredBy(r.Context(), organizationID, userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) transferSponsor(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	fromUserID, err := httpx.PathUUID(r, "userID", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		ToUserID uuid.UUID `json:"to_user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.TransferSponsor(r.Context(), organizationID, fromUserID, in.ToUserID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"transferred": n})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Delete(r.Context(), id, organizationID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) patch(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Back-compat: PATCH {disabled} maps onto the lifecycle state machine.
	target := "active"
	if in.Disabled {
		target = "suspended"
	}
	_, err = h.Service.Transition(r.Context(), id, organizationID, target, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) suspend(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "suspended")
}

func (h *Handler) resume(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "active")
}

func (h *Handler) decommission(w http.ResponseWriter, r *http.Request) {
	h.doTransition(w, r, "decommissioned")
}

// doTransition runs one lifecycle transition, audits it, and returns the new status.
func (h *Handler) doTransition(w http.ResponseWriter, r *http.Request, target string) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	_, err = h.Service.Transition(r.Context(), id, organizationID, target, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": target})
}

func (h *Handler) killAll(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.KillAll(r.Context(), organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"suspended": n})
}

// rotateSecret handles POST /v1/organizations/{organizationID}/agents/{id}/rotate-secret.
func (h *Handler) rotateSecret(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	overlap, err := rotation.Request(r, organizationID, id, h.Service.Scopes, h.GrantCheck)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	secret, until, err := h.Service.RotateSecret(r.Context(), organizationID, id, overlap, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "secret": secret, "previous_secret_expires_at": until,
	})
}

// resumeAll handles POST /v1/organizations/{organizationID}/agents/resume-all.
func (h *Handler) resumeAll(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.ResumeAll(r.Context(), organizationID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"resumed": n})
}
