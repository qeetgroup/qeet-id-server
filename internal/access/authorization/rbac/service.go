package rbac

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Service runs each RBAC mutation in its own transaction with its audit row;
// reads stay on the Repository.
type Service struct {
	repo    *Repository
	emitter EventEmitter
	limits  entitlements.PlanLimiter
	seats   entitlements.SeatGuard
	signals *sessionsignal.Signaller
}

// ServiceDeps are what the role and permission service is built from, all
// required.
type ServiceDeps struct {
	Emitter EventEmitter             // sends token.claims_change webhook events
	Limits  entitlements.PlanLimiter // caps custom roles by plan
	Seats   entitlements.SeatGuard   // keeps the people holding a role within the plan's seats
	Signals *sessionsignal.Signaller // announces the sessions a lost membership ends
}

// NewService returns the role and permission service over repo.
func NewService(repo *Repository, d ServiceDeps) (*Service, error) {
	switch {
	case d.Emitter == nil:
		return nil, errors.New("rbac: the role service needs an event emitter")
	case d.Limits == nil:
		return nil, errors.New("rbac: the role service needs a plan limiter")
	case d.Seats == nil:
		return nil, errors.New("rbac: the role service needs a seat guard")
	case d.Signals == nil:
		return nil, errors.New("rbac: the role service needs session signals")
	}
	return &Service{repo: repo, emitter: d.Emitter, limits: d.Limits, seats: d.Seats, signals: d.Signals}, nil
}

// seatLimit returns the organization's seat cap, negative for none.
func (s *Service) seatLimit(ctx context.Context, organizationID uuid.UUID) (int, error) {
	return s.seats.SeatLimit(ctx, organizationID)
}

// withinSeats runs change in tx through the seat guard.
func (s *Service) withinSeats(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int, change func() error) error {
	return s.seats.WithinSeats(ctx, tx, organizationID, limit, change)
}

// EventEmitter delivers a webhook event to an organization's subscriptions, as the
// webhooks service's Enqueue does, without rbac importing that package.
type EventEmitter func(ctx context.Context, organizationID uuid.UUID, eventType string, payload any) error

// emit delivers a webhook event, best effort: an error is ignored so it never
// fails the role change it describes.
func (s *Service) emit(ctx context.Context, organizationID uuid.UUID, eventType string, payload any) {
	_ = s.emitter(ctx, organizationID, eventType, payload)
}

// CreateRole adds a role to the organization, recorded as actor's.
func (s *Service) CreateRole(ctx context.Context, organizationID uuid.UUID, name, desc string, actor audit.Actor) (*Role, error) {
	// Plan gate: custom roles are capped by plan (Free allows none — built-in
	// roles don't count). Refuse once the cap is reached.
	lim, err := s.limits.Limit(ctx, organizationID, entitlements.LimitCustomRoles)
	if err != nil {
		return nil, err
	}
	if lim >= 0 {
		n, err := s.repo.CountCustomRoles(ctx, organizationID)
		if err != nil {
			return nil, err
		}
		if int(n) >= lim {
			return nil, errs.ErrPlanLimit.WithMetadata(map[string]any{"resource": entitlements.LimitCustomRoles, "limit": lim})
		}
	}
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	role, err := s.repo.CreateRole(ctx, tx, organizationID, name, desc, false)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "role.created", "role", role.ID,
		map[string]any{"name": role.Name, "is_system": role.IsSystem})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return role, nil
}

// GrantPermission adds a permission to organizationID's role roleID, recorded as
// actor's in the organization's audit log. The caller checks the role is organizationID's.
func (s *Service) GrantPermission(ctx context.Context, organizationID, roleID, permID uuid.UUID, actor audit.Actor) error {
	return s.changePermission(ctx, organizationID, roleID, permID, actor, "role.permission_granted", s.repo.GrantPermission)
}

// RevokePermission removes a permission from organizationID's role roleID, recorded
// as actor's in the organization's audit log. The caller checks the role is
// organizationID's.
func (s *Service) RevokePermission(ctx context.Context, organizationID, roleID, permID uuid.UUID, actor audit.Actor) error {
	return s.changePermission(ctx, organizationID, roleID, permID, actor, "role.permission_revoked", s.repo.RevokePermission)
}

// changePermission runs change on roleID and permID in one transaction with
// its audit record, action.
func (s *Service) changePermission(ctx context.Context, organizationID, roleID, permID uuid.UUID, actor audit.Actor, action string,
	change func(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	key, err := s.repo.PermissionKey(ctx, tx, permID)
	if err != nil {
		return err
	}
	if err := change(ctx, tx, roleID, permID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "role", roleID,
		map[string]any{"permission_id": permID, "permission": key})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AssignRole gives a user a role in the organization, granted by grantedBy and
// recorded as actor's. A user's first role takes a seat, refused with
// errs.ErrPlanLimit once the plan's seats are all taken.
func (s *Service) AssignRole(ctx context.Context, userID, organizationID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) error {
	limit, err := s.seatLimit(ctx, organizationID)
	if err != nil {
		return err
	}
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.withinSeats(ctx, tx, organizationID, limit, func() error {
		return s.repo.AssignRole(ctx, tx, userID, organizationID, roleID, grantedBy)
	}); err != nil {
		if errors.Is(err, errs.ErrRBACUserOrRoleNotFound) {
			_ = tx.Rollback(ctx)
			// In its own transaction, after the assignment's has rolled back, so
			// repeated attempts with another organization's ids stay visible.
			// The supplied ids are recorded as given.
			if aerr := audit.RecordAlone(ctx, s.repo.Pool(), actor.Event(organizationID, "role.assign_refused", "user", userID,
				map[string]any{"role_id": roleID})); aerr != nil {
				return aerr
			}
		}
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "role.assigned", "user", userID,
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
	s.emit(ctx, organizationID, "token.claims_change", map[string]any{
		"user_id": userID, "role_id": roleID, "change": "role_assigned",
	})
	return nil
}

// SeatLimit is the plan's seat limit for organizationID (negative: none), read before
// a transaction that gives a role with AssignRoleInTx.
func (s *Service) SeatLimit(ctx context.Context, organizationID uuid.UUID) (int, error) {
	return s.seatLimit(ctx, organizationID)
}

// AssignRoleInTx is AssignRole inside the caller's tx: the seat check, assignment and audit row commit
// or roll back with the caller's own work, such as answering an access request. limit is SeatLimit,
// read before tx began. After tx commits, call the returned function to send the token-change signal.
func (s *Service) AssignRoleInTx(ctx context.Context, tx pgx.Tx, limit int, userID, organizationID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) (func(), error) {
	if err := s.withinSeats(ctx, tx, organizationID, limit, func() error {
		return s.repo.AssignRole(ctx, tx, userID, organizationID, roleID, grantedBy)
	}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "role.assigned", "user", userID,
		map[string]any{"role_id": roleID})); err != nil {
		return nil, err
	}
	return func() {
		s.emit(ctx, organizationID, "token.claims_change", map[string]any{
			"user_id": userID, "role_id": roleID, "change": "role_assigned",
		})
	}, nil
}

// UnassignRole takes a role away from a user in the organization, recorded as
// actor's. Their last role in an organization that isn't their home ends their
// membership, so their sessions there end too, as removing them does.
func (s *Service) UnassignRole(ctx context.Context, userID, organizationID, roleID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.UnassignRole(ctx, tx, userID, organizationID, roleID); err != nil {
		return err
	}
	left, err := s.repo.LeftOrganization(ctx, tx, userID, organizationID)
	if err != nil {
		return err
	}
	if left {
		ended, err := sessionsignal.EndUserSessionsInOrganization(ctx, tx, userID, organizationID)
		if err != nil {
			return err
		}
		s.signals.Revoked(ctx, tx, sessionsignal.ReasonRemovedFromOrganization, ended...)
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "role.unassigned", "user", userID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.emit(ctx, organizationID, "token.claims_change", map[string]any{
		"user_id": userID, "role_id": roleID, "change": "role_unassigned",
	})
	return nil
}

// AssignRoleToGroup grants a role to a group, both of organizationID (a cross-organization or missing
// pair is ErrNotFound, not a silent no-op), audited like a user-role grant with the group as subject.
// Members who held no role take a seat each, refused with errs.ErrPlanLimit beyond the plan's seats.
func (s *Service) AssignRoleToGroup(ctx context.Context, groupID, organizationID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) error {
	limit, err := s.seatLimit(ctx, organizationID)
	if err != nil {
		return err
	}
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.withinSeats(ctx, tx, organizationID, limit, func() error {
		valid, err := s.repo.AssignRoleToGroup(ctx, tx, groupID, organizationID, roleID, grantedBy)
		if err == nil && !valid {
			err = ErrGroupOrRoleNotFound
		}
		return err
	}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "role.group_assigned", "group", groupID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveRoleFromGroup revokes a role from a group within an organization.
func (s *Service) RemoveRoleFromGroup(ctx context.Context, groupID, organizationID, roleID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.repo.RemoveRoleFromGroup(ctx, tx, groupID, organizationID, roleID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "role.group_unassigned", "group", groupID,
		map[string]any{"role_id": roleID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
