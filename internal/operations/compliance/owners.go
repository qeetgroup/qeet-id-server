package compliance

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// knownControl reports whether id is a control of a framework's catalog.
func knownControl(id string) bool {
	for _, catalog := range controlsByFramework {
		for _, c := range catalog {
			if c.id == id {
				return true
			}
		}
	}
	return false
}

// Owners returns who answers for each of organizationID's controls that has an
// owner.
func (s *EvidenceService) Owners(ctx context.Context, organizationID uuid.UUID) ([]ControlOwner, error) {
	rows, err := s.q.ListControlOwners(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]ControlOwner, len(rows))
	for i, r := range rows {
		out[i] = ControlOwner{ControlID: r.ControlID, UserID: r.UserID, Email: r.Email, DisplayName: r.DisplayName, UpdatedAt: r.UpdatedAt}
	}
	return out, nil
}

// SetOwner makes userID, one of organizationID's people, answer for controlID, as
// actor's change.
func (s *EvidenceService) SetOwner(ctx context.Context, organizationID uuid.UUID, controlID string, userID uuid.UUID, actor audit.Actor) error {
	if !knownControl(controlID) {
		return errs.ErrNotFound
	}
	member, err := s.q.IsOrganizationMember(ctx, dbgen.IsOrganizationMemberParams{UserID: userID, OrganizationID: &organizationID})
	if err != nil {
		return err
	}
	if !member {
		return errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "user_id", Code: "not_a_member", Message: "Choose one of the organization's people.",
		}})
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.q.WithTx(tx).UpsertControlOwner(ctx, dbgen.UpsertControlOwnerParams{
		OrganizationID: organizationID, ControlID: controlID, UserID: userID, UpdatedBy: actor.UserID,
	}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.control_owner_set", "user", userID,
		map[string]any{"control_id": controlID, "user_id": userID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveOwner leaves controlID without an owner, as actor's change.
func (s *EvidenceService) RemoveOwner(ctx context.Context, organizationID uuid.UUID, controlID string, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteControlOwner(ctx, dbgen.DeleteControlOwnerParams{OrganizationID: organizationID, ControlID: controlID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.control_owner_removed", "compliance_control", uuid.Nil,
		map[string]any{"control_id": controlID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ControlOwner is the person an organization has made answer for a control.
type ControlOwner struct {
	ControlID   string    `json:"control_id"`
	UserID      uuid.UUID `json:"user_id"`
	Email       *string   `json:"email"`
	DisplayName *string   `json:"display_name"`
	UpdatedAt   time.Time `json:"updated_at"`
}
