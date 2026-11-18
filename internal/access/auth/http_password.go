package auth

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type changePasswordInput struct {
	// Optional: required only when the account already has a password. A
	// password-less account (social / passkey signup) omits it to SET one.
	CurrentPassword string `json:"current_password" validate:"omitempty"`
	NewPassword     string `json:"new_password" validate:"required,max=256"`
}

// signInMethods reports how many ways the caller can sign in, so a client can
// disable or explain removing the last one before trying. The server refuses
// that removal anyway.
func (h *Handler) signInMethods(w http.ResponseWriter, r *http.Request) {
	userID, err := httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	m, err := h.Service.SignInMethods(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"password":          m.Password,
		"passkeys":          m.Passkeys,
		"linked_identities": m.LinkedIdentities,
		"total":             m.Total(),
	})
}

// passwordStatus reports whether the caller has a password set, so the account
// UI can offer "set a password" vs "change password".
func (h *Handler) passwordStatus(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	has, err := h.Service.HasPassword(r.Context(), *p.UserID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"has_password": has})
}

// changePassword rotates (or sets) a signed-in user's password — self-service
// and organization-independent (works before any org). Re-proving the current
// password is required only when one is already set; either way, other sessions
// are revoked.
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in changePasswordInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	if err := h.Service.ChangePassword(r.Context(), ChangePasswordInput{
		UserID: *p.UserID, KeepSessionID: *p.SessionID, OrganizationID: p.OrganizationID,
		Current: in.CurrentPassword, Next: in.NewPassword, Actor: audit.ActorOf(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Your password has been updated."})
}
