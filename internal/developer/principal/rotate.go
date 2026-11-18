package principal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/principal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// RotateSecret gives one of the organization's service principals a new secret,
// returned only now, and leaves the old one working for overlap (0: it stops
// at once). Recorded as actor's.
func (s *Service) RotateSecret(ctx context.Context, organizationID, id uuid.UUID, overlap time.Duration, actor audit.Actor) (string, time.Time, error) {
	if err := rotation.CheckOverlap(overlap, "secret"); err != nil {
		return "", time.Time{}, err
	}
	raw, _, err := codes.URLToken()
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().UTC().Add(overlap)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).RotateServicePrincipalSecret(ctx, dbgen.RotateServicePrincipalSecretParams{
		PreviousExpiresAt: &until, SecretHash: password.HashSecret(raw),
		ID: id, OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "service_principal.secret_rotated", "service_principal", id,
		map[string]any{"name": name, "old_secret_ends": until})); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return raw, until, nil
}

// Enable turns one of the organization's disabled service principals back on,
// recorded as actor's. Enabling one that is on changes nothing.
func (s *Service) Enable(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).EnableServicePrincipal(ctx, dbgen.EnableServicePrincipalParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "service_principal.enabled", "service_principal", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// pathIDs returns the organization and service principal a request names.
func pathIDs(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	id, err := httpx.PathUUID(r, "id", ErrInvalidID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return tid, id, nil
}

// Scopes returns the scopes of service principal id of organizationID, or ErrPrincipalNotFound.
func (s *Service) Scopes(ctx context.Context, organizationID, id uuid.UUID) ([]string, error) {
	scopes, err := s.q.ServicePrincipalScopes(ctx, dbgen.ServicePrincipalScopesParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return scopes, err
}
