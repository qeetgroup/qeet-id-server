package auth

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	limit := paging.Limit(r.URL.Query(), 50, 100)
	current := uuid.Nil
	if p.SessionID != nil {
		current = *p.SessionID
	}
	out, err := h.Service.ListSessionsPageFor(r.Context(), *p.UserID, current, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
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
	// Scope to the caller: revoking a session you don't own is a silent no-op.
	if err := h.Service.Logout(r.Context(), id, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"message": "Session revoked."})
}

// revokeOtherSessions handles POST /v1/auth/sessions/revoke-others. It ends
// every session of the caller except the current one and returns {"revoked": n}.
// Issued access tokens stay valid until they expire.
func (h *Handler) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	n, err := h.Service.RevokeOtherSessions(r.Context(), RevokeOtherSessionsInput{
		UserID: *p.UserID, CurrentSessionID: *p.SessionID, OrganizationID: p.OrganizationID, Actor: audit.ActorOf(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// revokeAllSessions handles POST /v1/auth/sessions/revoke-all. It signs the
// caller out everywhere and returns {"revoked": total} with a count per place.
// Issued access tokens stay valid until they expire; a repeat returns zeros.
func (h *Handler) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil || p.SessionID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	ended, err := h.Service.RevokeAllSessions(r.Context(), RevokeAllSessionsInput{
		UserID: *p.UserID, SessionID: *p.SessionID, OrganizationID: p.OrganizationID, Actor: audit.ActorOf(r),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Every hosted-login session has ended server-side, whichever browser holds
	// it; a browser calling directly also drops its cookie.
	ClearLoginSessionCookie(w, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"revoked":                ended.Total(),
		"sessions":               ended.Sessions,
		"hosted_login_sessions":  ended.LoginSessions,
		"app_grants":             ended.AppGrants,
		"trusted_devices":        ended.TrustedDevices,
		"pending_authorizations": ended.PendingAuthorizations,
	})
}
