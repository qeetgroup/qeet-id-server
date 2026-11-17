package user

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/users/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
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

// listPasskeys handles GET /v1/tenants/{tenantID}/users/{id}/passkeys: the
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
		if row.LastUsedAt.Valid {
			t := row.LastUsedAt.Time
			items[i].LastUsedAt = &t
		}
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(items))
}

// removePasskey handles DELETE /v1/tenants/{tenantID}/users/{id}/passkeys/
// {passkeyID}, for a lost device: like a second-factor reset it is the
// account's home organization's alone to make, and only while the account
// belongs to no other. Its last way to sign in isn't removed. Audited, and the
// person is emailed.
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
	passkeyID, err := uuid.Parse(chi.URLParam(r, "passkeyID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid passkeyID"))
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
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	// The account's other ways to sign in span its organizations.
	ctx = postgres.AcrossOrganizations(ctx)
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	methods, err := LockSignInMethods(ctx, tx, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	name, err := h.Repo.q.WithTx(tx).DeleteUserPasskey(ctx, dbgen.DeleteUserPasskeyParams{ID: passkeyID, UserID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if methods.Total() <= 1 {
		_ = tx.Rollback(ctx)
		by := Remover{UserID: actorID, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
		httpx.WriteError(w, r, RefuseLastMethodRemoval(ctx, h.Repo.Pool(), id, &organizationID, "passkey", passkeyID, by))
		return
	}
	passkeyName := ""
	if name != nil {
		passkeyName = *name
	}
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &organizationID,
		ActorUserID:    actorID,
		Action:         "passkey.admin_deleted",
		ResourceType:   "user",
		ResourceID:     &id,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       map[string]any{"passkey_id": passkeyID, "name": passkeyName},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.tellCredentialChange(ctx, organizationID, target.Email, credentialPasskeyRemoved, passkeyName)
	w.WriteHeader(http.StatusNoContent)
}

// endSession handles DELETE /v1/tenants/{tenantID}/users/{id}/sessions/
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
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid sessionID"))
		return
	}
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	sessionOrganization, err := h.Repo.q.WithTx(tx).EndMemberSession(ctx, dbgen.EndMemberSessionParams{ID: sessionID, UserID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &organizationID,
		ActorUserID:    actorID,
		Action:         "session.admin_revoked",
		ResourceType:   "user",
		ResourceID:     &id,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       map[string]any{"session_id": sessionID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.Signals.Revoked(ctx, tx, sessionsignal.ReasonAdminRevoked, sessionsignal.Session{ID: sessionID, UserID: id, OrganizationID: sessionOrganization})
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
