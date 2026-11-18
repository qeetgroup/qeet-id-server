// Package group manages an organization's group hierarchy, its members, group
// templates and bulk import. Roles granted to groups belong to the rbac
// package. Each mutation commits its audit row in the same transaction.
package group

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/group/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Group is an organization group.
type Group struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	ParentID       *uuid.UUID `json:"parent_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	CreatedAt      time.Time  `json:"created_at"`
	// MemberCount is set by List only; Create and Update leave it zero.
	MemberCount int `json:"member_count"`
	// Roles are the roles granted to the group itself, set by List only for a
	// caller who may read roles; absent otherwise.
	Roles *[]GroupRole `json:"roles,omitempty"`
}

// GroupRole is a role granted to a group.
type GroupRole struct {
	RoleID uuid.UUID `json:"role_id"`
	Name   string    `json:"name"`
}

// Service manages the groups. seats keeps the people holding a role, which a
// group can carry, within the plan's seats; nil turns that off.
type Service struct {
	pool  *pgxpool.Pool
	q     *dbgen.Queries
	seats entitlements.SeatGuard
}

// NewService returns the group service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// SetSeatGuard wires the seat limit (nil disables it).
func (s *Service) SetSeatGuard(g entitlements.SeatGuard) { s.seats = g }

// CreateInput is what Create takes.
type CreateInput struct {
	OrganizationID uuid.UUID  `json:"organization_id"`
	ParentID       *uuid.UUID `json:"parent_id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
}

// UpdateInput is a partial update: a field left out of the request keeps its
// current value. "parent_id": null makes the group top-level.
type UpdateInput struct {
	Name        *string      `json:"name"`
	Description *string      `json:"description"`
	ParentID    OptionalUUID `json:"parent_id"`
}

// OptionalUUID is a JSON field that can be left out, null, or a UUID. Set
// reports whether the request named it at all; ID is nil for null.
type OptionalUUID struct {
	Set bool
	ID  *uuid.UUID
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *OptionalUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.ID = nil
		return nil
	}
	var id uuid.UUID
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}
	o.ID = &id
	return nil
}

func groupFromInsertRow(row dbgen.InsertGroupRow) Group {
	return Group{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		ParentID:       row.ParentID,
		Name:           row.Name,
		Description:    row.Description,
		CreatedAt:      row.CreatedAt,
	}
}

func groupFromUpdateRow(row dbgen.UpdateGroupRow) Group {
	return Group{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		ParentID:       row.ParentID,
		Name:           row.Name,
		Description:    row.Description,
		CreatedAt:      row.CreatedAt,
	}
}

// errInvalidID refuses a group or template ID in the path that is no UUID.
var errInvalidID = errs.ErrBadRequest.WithDetail("invalid id")

// errGroupUnnamed refuses a group name that is empty once trimmed.
var errGroupUnnamed = errs.ErrValidationFailed.WithFields([]errs.FieldError{{
	Field: "name", Code: "required", Message: "Give the group a name.",
}})

// Create adds a group to the organization. Its name is trimmed and must be unique in
// the organization, ignoring case; a taken one returns ErrNameExists.
func (s *Service) Create(ctx context.Context, in CreateInput, actor audit.Actor) (*Group, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, errGroupUnnamed
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// The parent is caller-supplied and must be one of this organization's groups.
	if in.ParentID != nil {
		ok, err := s.q.WithTx(tx).GroupExists(ctx, dbgen.GroupExistsParams{ID: *in.ParentID, OrganizationID: in.OrganizationID})
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errs.ErrGroupParentNotFound
		}
	}
	row, err := s.q.WithTx(tx).InsertGroup(ctx, dbgen.InsertGroupParams{
		OrganizationID: in.OrganizationID,
		ParentID:       in.ParentID,
		Name:           in.Name,
		Description:    in.Description,
	})
	if postgres.IsUnique(err) {
		return nil, ErrNameExists
	}
	if err != nil {
		return nil, err
	}
	g := groupFromInsertRow(row)
	if err := audit.Record(ctx, tx, actor.Event(g.OrganizationID, "group.created", "group", g.ID,
		map[string]any{"name": g.Name, "parent_id": g.ParentID})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: g.ID, Topic: "group.events", EventType: "group.created", Payload: g}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &g, nil
}

// List returns the organization's groups with their member counts, counted in one
// LEFT JOIN rather than a query per group: at most paging.MaxListItems+1, as
// the handler truncates the rest.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Group, error) {
	rows, err := s.q.ListGroups(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(rows))
	for _, row := range rows {
		out = append(out, Group{
			ID: row.ID, OrganizationID: row.OrganizationID, ParentID: row.ParentID, Name: row.Name,
			Description: row.Description, CreatedAt: row.CreatedAt, MemberCount: int(row.MemberCount),
		})
	}
	return out, nil
}

// WithRoles sets on each of the organization's groups the roles granted to it, all
// read in one query.
func (s *Service) WithRoles(ctx context.Context, organizationID uuid.UUID, groups []Group) error {
	rows, err := s.q.ListGroupRoles(ctx, organizationID)
	if err != nil {
		return err
	}
	byGroup := map[uuid.UUID][]GroupRole{}
	for _, row := range rows {
		byGroup[row.GroupID] = append(byGroup[row.GroupID], GroupRole{RoleID: row.RoleID, Name: row.Name})
	}
	for i := range groups {
		roles := byGroup[groups[i].ID]
		if roles == nil {
			roles = []GroupRole{}
		}
		groups[i].Roles = &roles
	}
	return nil
}

// filterByRoles keeps the groups that grant role (when set) and that grant some
// or no role (grants "some" or "none"; "" for either).
func filterByRoles(groups []Group, role *uuid.UUID, grants string) []Group {
	out := groups[:0]
	for _, g := range groups {
		roles := *g.Roles
		if grants == "some" && len(roles) == 0 || grants == "none" && len(roles) > 0 {
			continue
		}
		if role != nil && !slices.ContainsFunc(roles, func(r GroupRole) bool { return r.RoleID == *role }) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// Delete removes one of the organization's groups and its subgroups, recorded as
// actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	name, err := s.q.WithTx(tx).DeleteGroup(ctx, dbgen.DeleteGroupParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrGroupNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group.deleted", "group", id,
		map[string]any{"name": name})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "group.events", EventType: "group.deleted", Payload: map[string]any{"id": id, "organization_id": organizationID, "name": name}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Update changes the fields in sets. A new name is trimmed and must be unique in
// the organization, ignoring case; a taken one returns ErrNameExists.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor) (*Group, error) {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			return nil, errGroupUnnamed
		}
		in.Name = &name
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	// A new parent must be one of this organization's groups, and not the group
	// itself or one of its subgroups, which would make the hierarchy loop.
	if in.ParentID.Set && in.ParentID.ID != nil {
		parent := *in.ParentID.ID
		ok, err := q.GroupExists(ctx, dbgen.GroupExistsParams{ID: parent, OrganizationID: organizationID})
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errs.ErrGroupParentNotFound
		}
		loops, err := q.IsGroupOrDescendant(ctx, dbgen.IsGroupOrDescendantParams{
			GroupID: id, OrganizationID: organizationID, CandidateID: parent,
		})
		if err != nil {
			return nil, err
		}
		if loops {
			return nil, ErrCycle
		}
	}
	row, err := q.UpdateGroup(ctx, dbgen.UpdateGroupParams{
		Name:           in.Name,
		Description:    in.Description,
		SetParent:      in.ParentID.Set,
		ParentID:       in.ParentID.ID,
		ID:             id,
		OrganizationID: organizationID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrGroupNotFound
	}
	if postgres.IsUnique(err) {
		return nil, ErrNameExists
	}
	if err != nil {
		return nil, err
	}
	g := groupFromUpdateRow(row)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group.updated", "group", id,
		map[string]any{"name": g.Name, "parent_id": g.ParentID})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "group.events", EventType: "group.updated", Payload: g}); err != nil {
		return nil, err
	}
	return &g, tx.Commit(ctx)
}
