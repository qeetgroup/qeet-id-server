package rbac

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Service wraps the Repository so each mutation owns its transaction and writes
// the audit row in the same tx — keeping the audit trail atomic with the change
// and the HTTP handlers thin. Reads stay on the Repository.
type Service struct {
	repo *Repository
	// emitter delivers token.claims_change signals to a tenant's webhook
	// subscriptions (nil = emission off). Set via SetEmitter.
	emitter EventEmitter
}

func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// EventEmitter delivers a webhook-shaped event to a tenant's subscriptions.
// Satisfied by *webhook.Service.Enqueue; kept as a func type (matching the
// same pattern used by domains/access/authentication and
// domains/developer/agents) so rbac doesn't import the webhooks package.
// Wired via SetEmitter.
type EventEmitter func(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error

// SetEmitter wires webhook delivery for token.claims_change signals. Called
// from cmd/server/main.go.
func (s *Service) SetEmitter(e EventEmitter) { s.emitter = e }

// emit is a best-effort webhook delivery — a failure here must never fail
// the role change it's describing, so errors are swallowed silently. (rbac
// has no logger dependency today; adding one for this alone isn't worth the
// new import — Enqueue's own dispatcher logs delivery failures.)
func (s *Service) emit(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) {
	if s.emitter == nil {
		return
	}
	_ = s.emitter(ctx, tenantID, eventType, payload)
}

func (s *Service) CreateRole(ctx context.Context, tenantID uuid.UUID, name, desc string, actor audit.Actor) (*Role, error) {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	role, err := s.repo.CreateRole(ctx, tx, tenantID, name, desc, false)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.created", "role", role.ID,
		map[string]any{"name": role.Name, "is_system": role.IsSystem})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return role, nil
}

func (s *Service) GrantPermission(ctx context.Context, roleID, permID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.GrantPermission(ctx, tx, roleID, permID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.PlatformEvent("role.permission_granted", "role", roleID,
		map[string]any{"permission_id": permID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) RevokePermission(ctx context.Context, roleID, permID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.RevokePermission(ctx, tx, roleID, permID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.PlatformEvent("role.permission_revoked", "role", roleID,
		map[string]any{"permission_id": permID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) AssignRole(ctx context.Context, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.AssignRole(ctx, tx, userID, tenantID, roleID, grantedBy); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.assigned", "user", userID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Best-effort, outside the tx: this user's effective permissions just
	// changed, so any access token they're already holding is now stale —
	// the CAEP-shaped "token-claims-change" signal a webhook subscriber can
	// react to instead of waiting for that token's TTL to lapse.
	s.emit(ctx, tenantID, "token.claims_change", map[string]any{
		"user_id": userID, "role_id": roleID, "change": "role_assigned",
	})
	return nil
}

func (s *Service) UnassignRole(ctx context.Context, userID, tenantID, roleID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.UnassignRole(ctx, tx, userID, tenantID, roleID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.unassigned", "user", userID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.emit(ctx, tenantID, "token.claims_change", map[string]any{
		"user_id": userID, "role_id": roleID, "change": "role_unassigned",
	})
	return nil
}

// AssignRoleToGroup grants a role to a group; both must belong to tenantID. A
// cross-tenant or missing role/group pair yields ErrNotFound rather than a
// silent no-op. Audits like the user-role grant, but the subject is the group.
func (s *Service) AssignRoleToGroup(ctx context.Context, groupID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	valid, err := s.repo.AssignRoleToGroup(ctx, tx, groupID, tenantID, roleID, grantedBy)
	if err != nil {
		return err
	}
	if !valid {
		return errs.ErrNotFound.WithDetail("group or role not found in tenant")
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.group_assigned", "group", groupID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveRoleFromGroup revokes a role from a group within a tenant.
func (s *Service) RemoveRoleFromGroup(ctx context.Context, groupID, tenantID, roleID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.RemoveRoleFromGroup(ctx, tx, groupID, tenantID, roleID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.group_unassigned", "group", groupID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
