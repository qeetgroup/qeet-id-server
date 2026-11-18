package auth

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// trustedDeviceCount reports how many live trusted devices the caller's organization
// has. Scoped from the principal, never a path or query parameter, so one organization
// can't read another's estate.
func (h *Handler) trustedDeviceCount(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.CountTrustedDevices(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// requestTrustedDevice is the trusted-device cookie the request carries, if
// any, so a list can mark the device it came from.
func requestTrustedDevice(r *http.Request) string {
	if c, err := r.Cookie(TrustedDeviceCookie); err == nil {
		return c.Value
	}
	return ""
}

// listOwnTrustedDevices → GET /v1/auth/trusted-devices: the caller's own
// remembered devices, in every organization.
func (h *Handler) listOwnTrustedDevices(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	out, err := h.Service.ListTrustedDevices(r.Context(), *p.UserID, nil, requestTrustedDevice(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// forgetOwnTrustedDevices → DELETE /v1/auth/trusted-devices[/{id}]: forget one
// of the caller's remembered devices, or all of them.
func (h *Handler) forgetOwnTrustedDevices(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	in := ForgetTrustedDevicesInput{UserID: *p.UserID, Actor: audit.ActorOf(r)}
	if chi.URLParam(r, "id") != "" {
		id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid id"))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		in.DeviceID = &id
	}
	n, err := h.Service.ForgetTrustedDevices(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"forgotten": n})
}

// listMemberTrustedDevices → GET /v1/users/{id}/trusted-devices: a member's
// devices remembered in the caller's organization.
func (h *Handler) listMemberTrustedDevices(w http.ResponseWriter, r *http.Request) {
	userID, organizationID, err := httpx.Member(r, "id", h.Service.IsMember)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListTrustedDevices(r.Context(), userID, &organizationID, "")
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// forgetMemberTrustedDevices → DELETE /v1/users/{id}/trusted-devices[/{deviceID}]:
// forget one or all of the devices remembered in the caller's organization of
// a member they outrank.
func (h *Handler) forgetMemberTrustedDevices(w http.ResponseWriter, r *http.Request) {
	userID, organizationID, err := httpx.MemberToActOn(r, "id", h.Service.IsMember, h.ActOnCheck)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in := ForgetTrustedDevicesInput{UserID: userID, OrganizationID: &organizationID, Actor: audit.ActorOf(r)}
	if chi.URLParam(r, "deviceID") != "" {
		id, err := httpx.PathUUID(r, "deviceID", errs.ErrBadRequest.WithDetail("invalid deviceID"))
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		in.DeviceID = &id
	}
	n, err := h.Service.ForgetTrustedDevices(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"forgotten": n})
}
