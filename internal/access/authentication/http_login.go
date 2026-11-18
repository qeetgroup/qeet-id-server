package authentication

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type loginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var in loginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	h.evalBot(r, in.Email)
	res, err := h.Service.Login(r.Context(), LoginInput{
		Email:    in.Email,
		Password: in.Password,
		Actor:    audit.ActorOf(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if res.MFARequired {
		// Password ok, but a second factor is required. No tokens yet — the
		// client completes the challenge at POST /v1/auth/mfa.
		httpx.WriteJSON(w, http.StatusOK, res.Body())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Pair)
}

type refreshInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var in refreshInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	pair, err := h.Service.Refresh(r.Context(), RefreshInput{
		RefreshToken: in.RefreshToken,
		Actor:        audit.ActorOf(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.SessionID == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if err := h.Service.Logout(r.Context(), *p.SessionID, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "You've been signed out."})
}

type switchOrganizationInput struct {
	OrganizationID string `json:"organization_id" validate:"required,uuid"`
}

// switchOrganization → POST /v1/auth/switch-organization. Replaces the caller's session
// with one in another organization they belong to (Service.SwitchOrganization); the
// session in the presented access token is the one that ends.
func (h *Handler) switchOrganization(w http.ResponseWriter, r *http.Request) {
	// The switch reads the target organization's policies and roles, so it runs
	// across organizations; membership of the target is checked below.
	r = r.WithContext(postgres.AcrossOrganizations(r.Context()))
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in switchOrganizationInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	tid, err := uuid.Parse(in.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid organization_id"))
		return
	}
	pair, err := h.Service.SwitchOrganization(r.Context(), SwitchOrganizationInput{
		UserID: *p.UserID, FromSessionID: *p.SessionID, OrganizationID: tid, Actor: audit.ActorOf(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":    pair.AccessToken,
		"token_type":      pair.TokenType,
		"expires_at":      pair.ExpiresAt,
		"refresh_token":   pair.RefreshToken,
		"session_id":      pair.SessionID,
		"user_id":         pair.UserID,
		"organization_id": tid,
	})
}
