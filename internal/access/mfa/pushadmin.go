package mfa

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// isMember reports whether userID belongs to organizationID, for the member routes.
func (h *Handler) isMember(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return h.Service.q.IsOrganizationMember(ctx, dbgen.IsOrganizationMemberParams{UserID: userID, OrganizationID: organizationID})
}

// listMemberPushDevices → GET /v1/users/{id}/push-devices.
func (h *Handler) listMemberPushDevices(w http.ResponseWriter, r *http.Request) {
	userID, _, err := httpx.Member(r, "id", h.isMember)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListPushDevices(r.Context(), userID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// revokeMemberPushDevice → DELETE /v1/users/{id}/push-devices/{deviceID}: an
// administrator disconnects a lost phone of a member they outrank.
func (h *Handler) revokeMemberPushDevice(w http.ResponseWriter, r *http.Request) {
	userID, organizationID, err := httpx.MemberToActOn(r, "id", h.isMember, h.ActOnCheck)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	deviceID, err := httpx.PathUUID(r, "deviceID", errs.ErrBadRequest.WithDetail("invalid deviceID"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx, by := r.Context(), audit.ActorOf(r)
	if err := h.Service.RevokePushDevice(ctx, userID, deviceID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Service.auditPushDevice(ctx, by, &organizationID, userID, deviceID, "mfa.push_device_revoked")
	w.WriteHeader(http.StatusNoContent)
}
