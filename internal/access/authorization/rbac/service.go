package rbac

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Service runs each RBAC mutation in its own transaction with its audit row;
// reads stay on the Repository. emitter sends token.claims_change webhook
// events and limits caps custom roles by plan; nil turns either off.
type Service struct {
	repo    *Repository
	emitter EventEmitter
	limits  PlanLimiter
}

// NewService returns the role and permission service.
func NewService(repo *Repository) *Service { return &Service{repo: repo} }

// PlanLimiter returns the cap for a plan-gated resource (negative: unlimited).
// It is satisfied by operations/entitlements.Service.
type PlanLimiter interface {
	Limit(ctx context.Context, tenantID uuid.UUID, resource string) (int, error)
}

// SetPlanLimiter wires the plan-limit checker (nil disables the gate).
func (s *Service) SetPlanLimiter(l PlanLimiter) { s.limits = l }

// EventEmitter delivers a webhook event to a tenant's subscriptions, as the
// webhooks service's Enqueue does, without rbac importing that package.
type EventEmitter func(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) error

// SetEmitter sets webhook delivery for token.claims_change events.
func (s *Service) SetEmitter(e EventEmitter) { s.emitter = e }

// emit delivers a webhook event, best effort: an error is ignored so it never
// fails the role change it describes.
func (s *Service) emit(ctx context.Context, tenantID uuid.UUID, eventType string, payload any) {
	if s.emitter == nil {
		return
	}
	_ = s.emitter(ctx, tenantID, eventType, payload)
}

// CreateRole adds a role to the tenant, recorded as actor's.
func (s *Service) CreateRole(ctx context.Context, tenantID uuid.UUID, name, desc string, actor audit.Actor) (*Role, error) {
	// Plan gate: custom roles are capped by plan (Free allows none — built-in
	// roles don't count). Refuse once the cap is reached.
	if s.limits != nil {
		lim, err := s.limits.Limit(ctx, tenantID, "custom_roles")
		if err != nil {
			return nil, err
		}
		if lim >= 0 {
			n, err := s.repo.CountCustomRoles(ctx, tenantID)
			if err != nil {
				return nil, err
			}
			if int(n) >= lim {
				return nil, errs.ErrPlanLimit.WithMetadata(map[string]any{"resource": "custom_roles", "limit": lim})
			}
		}
	}
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

// GrantPermission adds a permission to a role, recorded as actor's.
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

// RevokePermission removes a permission from a role, recorded as actor's.
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

// AssignRole gives a user a role in the tenant, granted by grantedBy and
// recorded as actor's.
func (s *Service) AssignRole(ctx context.Context, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.AssignRole(ctx, tx, userID, tenantID, roleID, grantedBy); err != nil {
		if errors.Is(err, errs.ErrRBACUserOrRoleNotFound) {
			_ = tx.Rollback(ctx)
			if aerr := s.recordAssignRefused(ctx, userID, tenantID, roleID, actor); aerr != nil {
				return aerr
			}
		}
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

// recordAssignRefused audits a refused role assignment in its own transaction,
// after the assignment's has rolled back, so repeated attempts with another
// tenant's ids stay visible. The supplied ids are recorded as given.
func (s *Service) recordAssignRefused(ctx context.Context, userID, tenantID, roleID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.assign_refused", "user", userID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnassignRole takes a role away from a user in the tenant, recorded as
// actor's.
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
		return errs.ErrRBACGroupOrRoleNotFound
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
