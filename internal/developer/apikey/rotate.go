package apikey

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Rotate replaces one of the organization's live keys with a new one of the same
// name, scopes, person and expiry, shown only now, and leaves the old one
// working for overlap (0: it stops at once). A key acting for a person is
// replaced only by that person, as only they may create one. Recorded as
// actor's.
func (s *Service) Rotate(ctx context.Context, organizationID, id uuid.UUID, overlap time.Duration, actor audit.Actor) (*Key, string, error) {
	if err := rotation.CheckOverlap(overlap, "key"); err != nil {
		return nil, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	old, err := q.LockAPIKeyForRotation(ctx, dbgen.LockAPIKeyForRotationParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", errs.ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if forUser := old.UserID; forUser != nil && (actor.UserID == nil || *forUser != *actor.UserID) {
		return nil, "", ErrUserNotSelf
	}
	prefix, secret, full, err := generateRaw()
	if err != nil {
		return nil, "", err
	}
	row, err := q.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		OrganizationID: organizationID, UserID: old.UserID, Name: old.Name, Prefix: prefix, KeyHash: password.HashSecret(secret),
		Scopes: old.Scopes, ExpiresAt: old.ExpiresAt, CreatedBy: actor.UserID, RotatedFrom: &id,
	})
	if err != nil {
		return nil, "", err
	}
	until := time.Now().UTC().Add(overlap)
	if err := q.EndAPIKeyAt(ctx, dbgen.EndAPIKeyAtParams{Until: until, ID: id, OrganizationID: organizationID}); err != nil {
		return nil, "", err
	}
	k := rowToKey(row.ID, row.OrganizationID, row.UserID, row.Name, row.Prefix,
		row.Scopes, row.ExpiresAt, row.LastUsedAt, row.RevokedAt, row.CreatedAt)
	k.CreatedBy, k.RotatedFrom = row.CreatedBy, row.RotatedFrom
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "apikey.rotated", "api_key", k.ID,
		map[string]any{"name": k.Name, "replaced": id, "old_key_ends": until})); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return &k, full, nil
}

// Scopes returns the scopes of API key id of organizationID, or ErrAPIKeyNotFound.
func (s *Service) Scopes(ctx context.Context, organizationID, id uuid.UUID) ([]string, error) {
	scopes, err := s.q.APIKeyScopes(ctx, dbgen.APIKeyScopesParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAPIKeyNotFound
	}
	return scopes, err
}
