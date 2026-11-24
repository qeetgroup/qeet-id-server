package oidc

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Grant is the current (not revoked, rotated or expired) refresh token of an OIDC authorization_code
// grant chain: an admin's active "access token" for a (client, user) pair. AuthorizedAt is when the
// grant began, LastUsedAt (and IssuedAt) the last token issue under it, ConsentedAt the person's last
// consent (nil when none was asked).
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

// GrantPage is a page of grants, with Total counting every grant the filter
// matches.
type GrantPage struct {
	paging.Result[Grant]
	Total int `json:"total"`
}

// ListGrants returns a page of up to limit (1..500, default 100) of the
// applications the organization's people have authorized, latest used first, after
// the cursor, of clientID when given.
func (s *Service) ListGrants(ctx context.Context, organizationID uuid.UUID, clientID *string, limit int, after paging.Cursor) (*GrantPage, error) {
	limit = paging.Clamp(limit, 100, 500)
	beforeTs, beforeID := time.Now().Add(time.Hour), uuid.Max
	if after.Set {
		beforeTs, beforeID = after.Time, after.ID
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
	items := make([]Grant, len(rows))
	for i, r := range rows {
		items[i] = Grant{
			ID: r.ID, ClientID: r.ClientID, ClientName: r.ClientName, UserID: r.UserID, UserEmail: r.UserEmail,
			UserName: r.UserName, Scopes: r.Scopes, AuthorizedAt: r.AuthorizedAt, ConsentedAt: r.ConsentedAt,
			LastUsedAt: r.IssuedAt, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		}
	}
	return &GrantPage{
		Result: paging.Page(paging.Next(items, limit, func(g Grant) (time.Time, uuid.UUID) { return g.IssuedAt, g.ID })),
		Total:  int(total),
	}, nil
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
			if err := audit.Record(ctx, tx, actor.Event(organizationID, "oauth.client_grants_revoked", "organization", organizationID,
				map[string]any{"client_id": clientID, "people": revoked})); err != nil {
				return 0, err
			}
		}
	} else {
		for _, id := range ids {
			clientID, user, err := s.revokeGrant(ctx, tx, organizationID, id)
			if errors.Is(err, ErrGrantNotFound) {
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

// RevokeGrant revokes, recorded as actor's, the entire (client, user)
// refresh-token chain the given token belongs to, so a rotated sibling can't
// keep the grant alive.
func (s *Service) RevokeGrant(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	clientID, user, err := s.revokeGrant(ctx, tx, organizationID, id)
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "oauth.grant_revoked", "oidc_grant", user,
		map[string]any{"client_id": clientID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// revokeGrant revokes, in tx, the chain the token id belongs to, and returns
// its client_id and person for the audit row.
func (s *Service) revokeGrant(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) (string, uuid.UUID, error) {
	q := s.q.WithTx(tx)
	row, err := q.GetGrantForRevoke(ctx, dbgen.GetGrantForRevokeParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", uuid.Nil, ErrGrantNotFound
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
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	q := r.URL.Query()
	var clientID *string
	if c := q.Get("client_id"); c != "" {
		clientID = &c
	}
	after, err := paging.ParseCursor(q)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListGrants(r.Context(), organizationID, clientID, paging.Limit(q, 100, 500), after)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// revokeGrants handles POST /v1/organizations/{organizationID}/oauth/grants/revoke.
func (h *Handler) revokeGrants(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
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
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RevokeGrant(r.Context(), organizationID, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
