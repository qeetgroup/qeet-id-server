package oidc

import (
	"context"
	"errors"
	"net/http"
	"strconv"
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
// "access token" for a (client, user) pair. AuthorizedAt is when the grant
// began; LastUsedAt (and IssuedAt) when the application was last issued tokens
// under it; ConsentedAt when the person last consented to the application,
// nil when it asked for no consent.
type Grant struct {
	ID           uuid.UUID  `json:"id"`
	ClientID     string     `json:"client_id"`
	ClientName   string     `json:"client_name"`
	UserID       uuid.UUID  `json:"user_id"`
	UserEmail    string     `json:"user_email"`
	UserName     *string    `json:"user_name"`
	Scopes       []string   `json:"scopes"`
	AuthorizedAt time.Time  `json:"authorized_at"`
	ConsentedAt  *time.Time `json:"consented_at"`
	LastUsedAt   time.Time  `json:"last_used_at"`
	IssuedAt     time.Time  `json:"issued_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
}

// GrantPage is a page of grants: NextCursor fetches the next, "" on the last,
// and Total counts every grant the filter matches.
type GrantPage struct {
	Items      []Grant `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
	Total      int     `json:"total"`
}

// ListGrants returns a page of up to limit (1..500, default 100) of the
// applications the organization's people have authorized, latest used first, after
// cursor, of clientID when given.
func (s *Service) ListGrants(ctx context.Context, organizationID uuid.UUID, clientID *string, limit int, cursor string) (*GrantPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	beforeTs, beforeID := time.Now().Add(time.Hour), uuid.Max
	if cursor != "" {
		var err error
		if beforeTs, beforeID, err = paging.DecodeTimeUUID(cursor); err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
	}
	total, err := s.q.CountGrants(ctx, dbgen.CountGrantsParams{OrganizationID: organizationID, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListGrants(ctx, dbgen.ListGrantsParams{
		OrganizationID: organizationID, ClientID: clientID, BeforeTs: beforeTs, BeforeID: beforeID, RowLimit: int32(limit + 1), // #nosec G115 -- limit is at most 500
	})
	if err != nil {
		return nil, err
	}
	page := &GrantPage{Items: make([]Grant, 0, len(rows)), Total: int(total)}
	for _, r := range rows {
		g := Grant{
			ID: r.ID, ClientID: r.ClientID, ClientName: r.ClientName, UserID: r.UserID, UserEmail: r.UserEmail,
			UserName: r.UserName, Scopes: r.Scopes, AuthorizedAt: r.AuthorizedAt, LastUsedAt: r.IssuedAt,
			IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		}
		if r.ConsentedAt.Valid {
			at := r.ConsentedAt.Time
			g.ConsentedAt = &at
		}
		page.Items = append(page.Items, g)
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = paging.EncodeTimeUUID(last.IssuedAt, last.ID)
	}
	return page, nil
}

// maxRevokeIDs bounds the grants one bulk revocation names.
const maxRevokeIDs = 100

// RevokeGrants ends, recorded as actor's, the grants ids name (their whole
// client-and-person chains), or every grant the organization's people gave clientID,
// and returns how many people's access it ended. Unknown ids are skipped.
func (s *Service) RevokeGrants(ctx context.Context, organizationID uuid.UUID, ids []uuid.UUID, clientID string, actor audit.Actor) (int, error) {
	if (len(ids) == 0) == (clientID == "") || len(ids) > maxRevokeIDs {
		return 0, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "ids", Code: "invalid", Message: "Name up to 100 grants, or one application, to revoke.",
		}})
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	revoked := 0
	if clientID != "" {
		users, err := s.q.WithTx(tx).RevokeClientGrants(ctx, dbgen.RevokeClientGrantsParams{OrganizationID: organizationID, ClientID: clientID})
		if err != nil {
			return 0, err
		}
		revoked = len(users)
		if revoked > 0 {
			if err := audit.Record(ctx, tx, actor.Event(organizationID, "oauth.client_grants_revoked", "tenant", organizationID,
				map[string]any{"client_id": clientID, "people": revoked})); err != nil {
				return 0, err
			}
		}
	} else {
		for _, id := range ids {
			clientID, user, err := s.RevokeGrant(ctx, tx, organizationID, id)
			if errors.Is(err, errs.ErrOIDCGrantNotFound) {
				continue
			}
			if err != nil {
				return 0, err
			}
			revoked++
			if err := audit.Record(ctx, tx, actor.Event(organizationID, "oauth.grant_revoked", "oidc_grant", user,
				map[string]any{"client_id": clientID})); err != nil {
				return 0, err
			}
		}
	}
	return revoked, tx.Commit(ctx)
}

// RevokeGrant revokes the entire (client, user) refresh-token chain the given
// token belongs to, so a rotated sibling can't keep the grant alive. Returns
// the client_id for the audit row.
func (s *Service) RevokeGrant(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) (string, uuid.UUID, error) {
	q := s.q.WithTx(tx)
	row, err := q.GetGrantForRevoke(ctx, dbgen.GetGrantForRevokeParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, errs.ErrOIDCGrantNotFound
	}
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := q.RevokeGrantChain(ctx, dbgen.RevokeGrantChainParams{
		ClientID: row.ClientID, UserID: row.UserID, OrganizationID: organizationID,
	}); err != nil {
		return "", uuid.Nil, err
	}
	return row.ClientID, row.UserID, nil
}

func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	var clientID *string
	if c := q.Get("client_id"); c != "" {
		clientID = &c
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	out, err := h.Service.ListGrants(r.Context(), organizationID, clientID, limit, q.Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// revokeGrants handles POST /v1/tenants/{tenantID}/oauth/grants/revoke.
func (h *Handler) revokeGrants(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		IDs      []uuid.UUID `json:"ids"`
		ClientID string      `json:"client_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Service.RevokeGrants(r.Context(), organizationID, in.IDs, in.ClientID, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

func (h *Handler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
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
	clientID, targetUser, err := h.Service.RevokeGrant(ctx, tx, organizationID, id)
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
	tid := organizationID
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid, ActorUserID: actorID, ActorType: actorType,
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
