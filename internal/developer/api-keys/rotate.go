package apikey

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Rotation overlaps: how long a replaced credential goes on working beside its
// replacement, by default and at most.
const (
	DefaultRotationOverlap = 24 * time.Hour
	MaxRotationOverlap     = 7 * 24 * time.Hour
)

// Rotate replaces one of the tenant's live keys with a new one of the same
// name, scopes, person and expiry, shown only now, and leaves the old one
// working for overlap (0: it stops at once). A key acting for a person is
// replaced only by that person, as only they may create one. Recorded as
// actor's.
func (s *Service) Rotate(ctx context.Context, tenantID, id uuid.UUID, overlap time.Duration, actor audit.Actor) (*Key, string, error) {
	if overlap < 0 || overlap > MaxRotationOverlap {
		return nil, "", errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "overlap_hours", Code: "out_of_range", Message: "Keep the old key working for 0 to 168 hours.",
		}})
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	old, err := q.LockAPIKeyForRotation(ctx, dbgen.LockAPIKeyForRotationParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", errs.ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if forUser := uuidPtr(old.UserID); forUser != nil && (actor.UserID == nil || *forUser != *actor.UserID) {
		return nil, "", errs.ErrAPIKeyUserNotSelf
	}
	prefix, secret, full, err := generateRaw()
	if err != nil {
		return nil, "", err
	}
	row, err := q.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		TenantID: tenantID, UserID: old.UserID, Name: old.Name, Prefix: prefix, KeyHash: password.HashSecret(secret),
		Scopes: old.Scopes, ExpiresAt: old.ExpiresAt, CreatedBy: pgUUID(actor.UserID), RotatedFrom: pgUUID(&id),
	})
	if err != nil {
		return nil, "", err
	}
	until := time.Now().UTC().Add(overlap)
	if err := q.EndAPIKeyAt(ctx, dbgen.EndAPIKeyAtParams{Until: until, ID: id, TenantID: tenantID}); err != nil {
		return nil, "", err
	}
	k := rowToKey(row.ID, row.TenantID, row.UserID, row.Name, row.Prefix,
		row.Scopes, row.ExpiresAt, row.LastUsedAt, row.RevokedAt, row.CreatedAt)
	k.CreatedBy, k.RotatedFrom = uuidPtr(row.CreatedBy), uuidPtr(row.RotatedFrom)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "apikey.rotated", "api_key", k.ID,
		map[string]any{"name": k.Name, "replaced": id, "old_key_ends": until})); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return &k, full, nil
}

// overlapOf reads a rotation request's overlap_hours, the default when absent.
func overlapOf(r *http.Request) (time.Duration, error) {
	var in struct {
		OverlapHours *int `json:"overlap_hours"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			return 0, err
		}
	}
	if in.OverlapHours == nil {
		return DefaultRotationOverlap, nil
	}
	return time.Duration(*in.OverlapHours) * time.Hour, nil
}

// rotate handles POST /v1/tenants/{tenantID}/api-keys/{id}/rotate.
func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathTenantOr(r, errs.ErrAPIKeyInvalidID, errs.ErrForbidden)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAPIKeyInvalidID)
		return
	}
	overlap, err := overlapOf(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.GrantCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	// The replacement carries the old key's scopes, which the caller must hold.
	keys, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for _, k := range keys {
		if k.ID == id {
			if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, k.Scopes); err != nil {
				httpx.WriteError(w, r, err)
				return
			}
		}
	}
	k, raw, err := h.Service.Rotate(r.Context(), tid, id, overlap, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"api_key": k,
		"secret":  raw,
		"warning": "This secret is only shown once. Store it now. The old key stops at the end of the overlap.",
	})
}
