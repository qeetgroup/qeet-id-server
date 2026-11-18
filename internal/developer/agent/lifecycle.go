package agent

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/agent/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// agentTransitions maps a target status to the source statuses it may come from.
var agentTransitions = map[string][]string{
	"suspended":      {"active"},              // suspend
	"active":         {"suspended"},           // resume
	"decommissioned": {"active", "suspended"}, // terminal
}

// transitionEvent maps a target status to its webhook/audit event verb.
var transitionEvent = map[string]string{
	"active":         "resumed",
	"suspended":      "suspended",
	"decommissioned": "decommissioned",
}

// validateTransition reports whether an agent may move from cur to target.
// Pure (no I/O) so it is unit-testable. A no-op (cur == target) is allowed.
func validateTransition(cur, target string) error {
	froms, ok := agentTransitions[target]
	if !ok {
		return ErrStatusInvalid
	}
	if cur == target {
		return nil
	}
	if cur == "decommissioned" {
		return ErrDecommissioned
	}
	if slices.Contains(froms, cur) {
		return nil
	}
	return ErrTransitionInvalid
}

// Transition moves an agent to target (active, suspended or decommissioned)
// after enforcing the allowed source states, recorded as actor's. Returns the
// previous status. Emits a webhook event (best-effort) on a real change.
func (s *Service) Transition(ctx context.Context, id, organizationID uuid.UUID, target string, actor audit.Actor) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	cur, err := q.LockAgentStatus(ctx, dbgen.LockAgentStatusParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrAgentNotFound
	}
	if err != nil {
		return "", err
	}
	if verr := validateTransition(cur, target); verr != nil {
		return cur, verr
	}
	if cur == target {
		return cur, nil
	}
	if err := q.SetAgentStatus(ctx, dbgen.SetAgentStatusParams{Status: target, ID: id, OrganizationID: organizationID}); err != nil {
		return cur, err
	}
	eventType := "agent." + transitionEvent[target]
	payload := map[string]any{
		"agent_id": id.String(), "organization_id": organizationID.String(),
		"previous_status": cur, "status": target,
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, eventType, "agent", id,
		map[string]any{"previous_status": cur, "status": target})); err != nil {
		return cur, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "agent.events", EventType: eventType, Payload: payload}); err != nil {
		return cur, err
	}
	if err := tx.Commit(ctx); err != nil {
		return cur, err
	}
	return cur, nil
}

// KillAll suspends every active agent for an organization in one statement (security
// incident response). Returns the number suspended and emits a single
// kill-switch webhook event.
func (s *Service) KillAll(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).KillAllAgents(ctx, organizationID)
	if err != nil {
		return 0, err
	}
	count := int(n)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.kill_switch", "organization", organizationID,
		map[string]any{"suspended": count})); err != nil {
		return 0, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: organizationID, Topic: "agent.events", EventType: "agent.kill_switch",
		Payload: map[string]any{"organization_id": organizationID, "suspended": count},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
