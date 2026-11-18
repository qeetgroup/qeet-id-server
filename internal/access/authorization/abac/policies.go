package abac

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Policy is the read-projection of one abac_policies row.
type Policy struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Effect         string          `json:"effect"`
	ResourceType   string          `json:"resource_type"`
	Action         string          `json:"action"`
	Condition      json.RawMessage `json:"condition"`
	Priority       int             `json:"priority"`
	Enabled        bool            `json:"enabled"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	// Version counts the policy's saves from 1, and UpdatedBy is who made the
	// last, nil for a machine or before it was kept.
	Version   int        `json:"version"`
	UpdatedBy *uuid.UUID `json:"updated_by"`
}

// CreateInput carries the user-supplied fields for a new policy.
type CreateInput struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Effect       string          `json:"effect"`
	ResourceType string          `json:"resource_type"`
	Action       string          `json:"action"`
	Condition    json.RawMessage `json:"condition"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
}

// UpdateInput is a policy's full replacement state for PATCH: every field,
// zero or not, replaces the stored one.
type UpdateInput struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Effect       string          `json:"effect"`
	ResourceType string          `json:"resource_type"`
	Action       string          `json:"action"`
	Condition    json.RawMessage `json:"condition"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
}

// toPolicy maps a generated AuthAbacPolicy row to the domain Policy type.
func toPolicy(row dbgen.AuthAbacPolicy) *Policy {
	p := &Policy{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Name:           row.Name,
		Description:    row.Description,
		Effect:         row.Effect,
		ResourceType:   row.ResourceType,
		Action:         row.Action,
		Priority:       int(row.Priority),
		Enabled:        row.Enabled,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
		Version:        int(row.Version),
	}
	p.UpdatedBy = row.UpdatedBy
	if len(row.Condition) > 0 {
		p.Condition = json.RawMessage(row.Condition)
	} else {
		p.Condition = json.RawMessage(`{}`)
	}
	return p
}

// Create inserts a new ABAC policy. The audit row and outbox event are
// committed atomically in the same transaction.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, in CreateInput, actor audit.Actor) (*Policy, error) {
	// Plan gate: ABAC (attribute-based access control) is a Pro+ feature.
	allowed, err := s.gate.FeatureAllowed(ctx, organizationID, "abac")
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "abac"})
	}
	cond, err := checkPolicy(in.Name, in.Effect, in.ResourceType, in.Action, in.Condition)
	if err != nil {
		return nil, err
	}
	if locked, err := s.locksOutAuthor(ctx, organizationID, in.Effect, in.ResourceType, in.Action, in.Enabled, cond, actor); err != nil {
		return nil, err
	} else if locked {
		return nil, ErrPolicyLocksOut
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	defer s.forgetPresence(organizationID)

	row, err := s.q.WithTx(tx).CreateAbacPolicy(ctx, dbgen.CreateAbacPolicyParams{
		OrganizationID: organizationID,
		Name:           in.Name,
		Description:    in.Description,
		Effect:         in.Effect,
		ResourceType:   in.ResourceType,
		Action:         in.Action,
		Condition:      []byte(cond),
		Priority:       int32(in.Priority), // #nosec G115 -- only orders the trace; deny wins regardless
		Enabled:        in.Enabled,
		UpdatedBy:      actor.UserID,
	})
	if err != nil {
		if postgres.IsUnique(err) {
			return nil, ErrPolicyNameExists
		}
		return nil, err
	}
	p := toPolicy(row)
	if err := s.q.WithTx(tx).SaveAbacPolicyVersion(ctx, dbgen.SaveAbacPolicyVersionParams{ID: p.ID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}

	if err := audit.Record(ctx, tx, actor.Event(organizationID, "abac_policy.created", "abac_policy", p.ID,
		map[string]any{"name": p.Name, "effect": p.Effect, "resource_type": p.ResourceType, "action": p.Action, "version": p.Version})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: p.ID,
		Topic:       "abac.events",
		EventType:   "abac_policy.created",
		Payload:     p,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Get returns one policy by id, scoped to organization.
func (s *Service) Get(ctx context.Context, id, organizationID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetAbacPolicy(ctx, dbgen.GetAbacPolicyParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toPolicy(row), nil
}

// List returns all policies for an organization, ordered by priority desc then name.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Policy, error) {
	rows, err := s.q.ListAbacPolicies(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Policy, 0, len(rows))
	for _, row := range rows {
		out = append(out, *toPolicy(row))
	}
	return out, nil
}

// Update replaces all mutable fields of a policy. The audit row and outbox
// event are committed atomically in the same transaction.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor) (*Policy, error) {
	return s.update(ctx, id, organizationID, in, actor, 0)
}

// update saves in as the policy's next version, recorded as restoring version
// restoredFrom when it isn't 0.
func (s *Service) update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor, restoredFrom int) (*Policy, error) {
	cond, err := checkPolicy(in.Name, in.Effect, in.ResourceType, in.Action, in.Condition)
	if err != nil {
		return nil, err
	}
	if locked, err := s.locksOutAuthor(ctx, organizationID, in.Effect, in.ResourceType, in.Action, in.Enabled, cond, actor); err != nil {
		return nil, err
	} else if locked {
		return nil, ErrPolicyLocksOut
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	defer s.forgetPresence(organizationID)

	row, err := s.q.WithTx(tx).UpdateAbacPolicy(ctx, dbgen.UpdateAbacPolicyParams{
		Name:           in.Name,
		Description:    in.Description,
		Effect:         in.Effect,
		ResourceType:   in.ResourceType,
		Action:         in.Action,
		Condition:      []byte(cond),
		Priority:       int32(in.Priority), // #nosec G115 -- only orders the trace; deny wins regardless
		Enabled:        in.Enabled,
		UpdatedBy:      actor.UserID,
		ID:             id,
		OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		if postgres.IsUnique(err) {
			return nil, ErrPolicyNameExists
		}
		return nil, err
	}
	p := toPolicy(row)
	if err := s.q.WithTx(tx).SaveAbacPolicyVersion(ctx, dbgen.SaveAbacPolicyVersionParams{ID: p.ID, OrganizationID: organizationID}); err != nil {
		return nil, err
	}

	action, meta := "abac_policy.updated", map[string]any{
		"name": p.Name, "effect": p.Effect, "resource_type": p.ResourceType, "action": p.Action, "version": p.Version,
	}
	if restoredFrom > 0 {
		action, meta["restored_from"] = "abac_policy.restored", restoredFrom
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "abac_policy", p.ID, meta)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: p.ID,
		Topic:       "abac.events",
		EventType:   "abac_policy.updated",
		Payload:     p,
	}); err != nil {
		return nil, err
	}
	return p, tx.Commit(ctx)
}

// Delete removes one policy by id, scoped to organization.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	defer s.forgetPresence(organizationID)

	name, err := s.q.WithTx(tx).DeleteAbacPolicy(ctx, dbgen.DeleteAbacPolicyParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}

	if err := audit.Record(ctx, tx, actor.Event(organizationID, "abac_policy.deleted", "abac_policy", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: id,
		Topic:       "abac.events",
		EventType:   "abac_policy.deleted",
		Payload:     map[string]any{"id": id, "organization_id": organizationID, "name": name},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
