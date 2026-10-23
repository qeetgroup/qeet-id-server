package oidc

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Grant is the current (non-revoked, non-rotated, unexpired) refresh token in
// an OIDC authorization_code grant chain — what an admin sees as an active
// "access token" for a (client, user) pair.
type Grant struct {
	ID        uuid.UUID `json:"id"`
	ClientID  string    `json:"client_id"`
	UserID    uuid.UUID `json:"user_id"`
	UserEmail string    `json:"user_email"`
	Scopes    []string  `json:"scopes"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ListGrants returns the applications the tenant's people have authorized.
func (s *Service) ListGrants(ctx context.Context, tenantID uuid.UUID) ([]Grant, error) {
	rows, err := s.q.ListGrants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Grant, len(rows))
	for i, r := range rows {
		out[i] = Grant{
			ID: r.ID, ClientID: r.ClientID, UserID: r.UserID, UserEmail: r.UserEmail,
			Scopes: r.Scopes, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		}
	}
	return out, nil
}

// RevokeGrant revokes the entire (client, user) refresh-token chain the given
// token belongs to, so a rotated sibling can't keep the grant alive. Returns
// the client_id for the audit row.
func (s *Service) RevokeGrant(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) (string, uuid.UUID, error) {
	q := s.q.WithTx(tx)
	row, err := q.GetGrantForRevoke(ctx, dbgen.GetGrantForRevokeParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrOIDCGrantNotFound
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := q.RevokeGrantChain(ctx, dbgen.RevokeGrantChainParams{
		ClientID: row.ClientID, UserID: row.UserID, TenantID: tenantID,
	}); err != nil {
		return "", uuid.Nil, err
	}
	return row.ClientID, row.UserID, nil
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListGrants(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrOIDCIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	clientID, targetUser, err := h.Service.RevokeGrant(ctx, tx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
	}
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "oauth.grant_revoked", ResourceType: "oidc_grant", ResourceID: &targetUser,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"client_id": clientID},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
