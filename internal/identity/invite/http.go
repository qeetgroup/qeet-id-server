package invite

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// tokenIssuer is the part of auth.Service this handler needs. Both methods honour
// the joined organization's second-factor requirement: a new account may get the
// enrolment challenge, and a signed-in one is refused if its session lacks a
// required factor.
type tokenIssuer interface {
	SignInInvitedAccount(ctx context.Context, userID, organizationID uuid.UUID, ip, ua string) (*auth.LoginResult, error)
	EnterInvitedOrganization(ctx context.Context, userID, organizationID, fromSessionID uuid.UUID, ip, ua string) (*auth.TokenPair, error)
}

// enterAsSignedIn answers an accept by a signed-in account with the token
// pair for the organization it joined.
func (h *Handler) enterAsSignedIn(w http.ResponseWriter, r *http.Request, p *httpx.Principal, res *AcceptResult) {
	from := uuid.Nil
	if p.SessionID != nil {
		from = *p.SessionID
	}
	pair, err := h.AuthService.EnterInvitedOrganization(r.Context(), res.UserID, res.OrganizationID, from, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

// Handler serves the invitation HTTP API.
type Handler struct {
	Service     *Service
	AuthService tokenIssuer
	Validate    *validator.Validate
	// GrantCheck refuses an invitation whose role would give the invitee
	// authority the caller doesn't hold (rbac.Repository.CheckGrantRole).
	// Without it an invitation that carries a role is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID, roleID uuid.UUID) error
}

// MountAuthed mounts the admin-side CRUD that requires authentication, plus the
// invitee-facing self-service accept for a user who is already signed in.
func (h *Handler) MountAuthed(r chi.Router) {
	r.Post("/invites", h.create)
	r.Get("/organizations/{organizationID}/invites", h.list)
	r.Post("/invites/{id}/resend", h.resend)
	r.Delete("/invites/{id}", h.revoke)
	// Self-service (possibly org-less): discover pending invites addressed to
	// my email, and accept one — by token (email link) or by id (from the
	// inbox) — joining with my existing account.
	r.Get("/me/invites", h.listMine)
	r.Post("/me/invites/accept", h.acceptAuthenticated)
	r.Post("/me/invites/{id}/accept", h.acceptMineByID)
	r.Post("/me/invites/{id}/decline", h.declineMine)
}

// MountPublic mounts the invitee-facing endpoints: accepting with a password,
// and looking an invitation up to choose how to accept it.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/invites/accept", h.accept)
	r.Post("/invites/lookup", h.lookup)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	if in.RoleID != nil {
		if h.GrantCheck == nil {
			httpx.WriteError(w, r, errs.ErrNotImplemented)
			return
		}
		if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, *in.RoleID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	// The token goes only to the invitee, by email: the invitation link is
	// proof of the address.
	iv, _, err := h.Service.Create(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"invite": iv})
}

func (h *Handler) resend(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Resending revives the invitation, so its role is held to the check
	// creating it is.
	role, err := h.Service.RoleOf(r.Context(), tid, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if role != nil {
		if h.GrantCheck == nil {
			httpx.WriteError(w, r, errs.ErrNotImplemented)
			return
		}
		if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, *role); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	iv, _, err := h.Service.Resend(r.Context(), tid, id, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"invite": iv})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Revoke(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) accept(w http.ResponseWriter, r *http.Request) {
	var in AcceptInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	res, err := h.Service.Accept(r.Context(), in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.AuthService.SignInInvitedAccount(r.Context(), res.UserID, res.OrganizationID, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if out.MFARequired {
		httpx.WriteJSON(w, http.StatusOK, out.Body())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out.Pair)
}

// listMine returns pending invitations addressed to the signed-in user's email.
// These handlers act on invitations from any organization, so they run across
// organizations; each finds the invitation by the caller's own email.
func (h *Handler) listMine(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	items, err := h.Service.ListForUser(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

// declineMine dismisses a pending invite from the caller's inbox.
func (h *Handler) declineMine(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.DeclineForUser(r.Context(), *p.UserID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Invitation declined."})
}

// acceptMineByID accepts a pending invite chosen from the caller's inbox.
func (h *Handler) acceptMineByID(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.AcceptAuthenticatedByID(r.Context(), *p.UserID, id, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.enterAsSignedIn(w, r, p, res)
}

type acceptAuthedInput struct {
	Token string `json:"token" validate:"required"`
}

// acceptAuthenticated joins the caller's existing account to the invited organization
// and returns an organization-scoped token pair so the client can switch straight in.
func (h *Handler) acceptAuthenticated(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in acceptAuthedInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	res, err := h.Service.AcceptAuthenticated(r.Context(), *p.UserID, in.Token, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.enterAsSignedIn(w, r, p, res)
}
