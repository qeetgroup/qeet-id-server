package group

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/group/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// AddMember adds a user to one of the organization's groups, recorded as actor's.
// Joining a group that carries a role gives a user holding none a seat,
// refused with errs.ErrPlanLimit once the plan's seats are all taken.
func (s *Service) AddMember(ctx context.Context, groupID, userID, organizationID uuid.UUID, actor audit.Actor) error {
	limit, err := s.seats.SeatLimit(ctx, organizationID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Only add to a group that belongs to this organization.
	exists, err := s.q.WithTx(tx).GroupExists(ctx, dbgen.GroupExistsParams{ID: groupID, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if !exists {
		return errs.ErrGroupNotFound
	}
	// Only add someone who is a live member of this organization; the insert checks it.
	insert := func() error {
		valid, err := s.q.WithTx(tx).InsertGroupMember(ctx, dbgen.InsertGroupMemberParams{
			GroupID: groupID, UserID: userID, OrganizationID: organizationID,
		})
		if err == nil && !valid {
			err = errs.ErrGroupUserNotFound
		}
		return err
	}
	if err := s.seats.WithinSeats(ctx, tx, organizationID, limit, insert); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group.member_added", "group", groupID,
		map[string]any{"user_id": userID})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: "group.member_added", Payload: map[string]any{"group_id": groupID, "user_id": userID, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveMember removes a user from one of the organization's groups, recorded as
// actor's.
func (s *Service) RemoveMember(ctx context.Context, groupID, userID, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	n, err := s.q.WithTx(tx).DeleteGroupMember(ctx, dbgen.DeleteGroupMemberParams{
		GroupID: groupID, UserID: userID, OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	// Nothing was removed, so there is nothing to audit or announce.
	if n == 0 {
		return nil
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "group.member_removed", "group", groupID,
		map[string]any{"user_id": userID})); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: groupID, Topic: "group.events", EventType: "group.member_removed", Payload: map[string]any{"group_id": groupID, "user_id": userID, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Member is a group member with the user's email and display name.
type Member struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
}

// ListMembers returns the members of one of the organization's groups.
func (s *Service) ListMembers(ctx context.Context, groupID, organizationID uuid.UUID) ([]Member, error) {
	rows, err := s.q.ListGroupMembers(ctx, dbgen.ListGroupMembersParams{GroupID: groupID, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		out = append(out, Member{
			UserID:      row.UserID,
			Email:       row.Email,
			DisplayName: row.DisplayName,
		})
	}
	return out, nil
}
