package user

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// MemberPasskey is one of a member's passkeys as an administrator sees it.
type MemberPasskey struct {
	ID         uuid.UUID  `json:"id"`
	Name       *string    `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// listPasskeys handles GET /v1/organizations/{organizationID}/users/{id}/passkeys: the
// member's passkeys.
func (h *Handler) listPasskeys(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.PathOrganization(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, _, err := h.memberID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rows, err := h.Repo.q.ListUserPasskeys(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items := make([]MemberPasskey, len(rows))
	for i, row := range rows {
		items[i] = MemberPasskey{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt}
		items[i].LastUsedAt = row.LastUsedAt
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

// removePasskey handles DELETE /v1/organizations/{organizationID}/users/{id}/passkeys/{passkeyID},
// for a lost device: like a second-factor reset, only the account's home organization may, and only
// while the account belongs to no other. Its last way to sign in isn't removed. Audited and emailed.
func (h *Handler) removePasskey(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.PathOrganization(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, organizationID, err := h.actOnID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	passkeyID, err := httpx.PathUUID(r, "passkeyID", errs.ErrBadRequest.WithDetail("invalid passkeyID"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if err := h.refuseSharedCredentials(ctx, id, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	target, err := h.Repo.Get(ctx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	passkeyName, err := h.accounts().removePasskey(ctx, organizationID, id, passkeyID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.tellCredentialChange(ctx, organizationID, target.Email, credentialPasskeyRemoved, passkeyName)
	w.WriteHeader(http.StatusNoContent)
}

// endSession handles DELETE /v1/organizations/{organizationID}/users/{id}/sessions/
// {sessionID}: one of the member's sessions in the caller's organization, as
// GET /v1/users/{id}/sessions lists them, ends. Audited and announced as
// session.revoked.
func (h *Handler) endSession(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.PathOrganization(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, organizationID, err := h.memberID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.checkActOn(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sessionID, err := httpx.PathUUID(r, "sessionID", errs.ErrBadRequest.WithDetail("invalid sessionID"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.accounts().endSession(r.Context(), organizationID, id, sessionID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
