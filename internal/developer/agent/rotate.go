package agent

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/agent/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// RotateSecret gives one of the organization's agents that isn't decommissioned a new
// secret, returned only now, and leaves the old one working for overlap (0: it
// stops at once). Recorded as actor's.
func (s *Service) RotateSecret(ctx context.Context, organizationID, id uuid.UUID, overlap time.Duration, actor audit.Actor) (string, time.Time, error) {
	if err := rotation.CheckOverlap(overlap, "secret"); err != nil {
		return "", time.Time{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return "", time.Time{}, err
	}
	until := time.Now().UTC().Add(overlap)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	name, err := s.q.WithTx(tx).RotateAgentSecret(ctx, dbgen.RotateAgentSecretParams{
		PreviousExpiresAt: &until, SecretHash: password.HashSecret(secret),
		ID: id, OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, errs.ErrAgentNotFound
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.secret_rotated", "agent", id,
		map[string]any{"name": name, "old_secret_ends": until})); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return secret, until, nil
}

// ResumeAll makes every suspended agent of an organization active again in one
// statement, the undoing of KillAll. Returns the number resumed and emits a
// single webhook event.
func (s *Service) ResumeAll(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).ResumeAllAgents(ctx, organizationID)
	if err != nil {
		return 0, err
	}
	count := int(n)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.resume_all", "organization", organizationID,
		map[string]any{"resumed": count})); err != nil {
		return 0, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: organizationID, Topic: "agent.events", EventType: "agent.resume_all",
		Payload: map[string]any{"organization_id": organizationID, "resumed": count},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

// Scopes returns the scopes of agent id of organizationID, or ErrAgentNotFound.
func (s *Service) Scopes(ctx context.Context, organizationID, id uuid.UUID) ([]string, error) {
	scopes, err := s.q.AgentScopes(ctx, dbgen.AgentScopesParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAgentNotFound
	}
	return scopes, err
}
