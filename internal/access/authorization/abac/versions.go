package abac

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// PolicyVersion is a policy as one of its saves left it, and who made it.
type PolicyVersion struct {
	Version      int             `json:"version"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Effect       string          `json:"effect"`
	ResourceType string          `json:"resource_type"`
	Action       string          `json:"action"`
	Condition    json.RawMessage `json:"condition"`
	Priority     int             `json:"priority"`
	Enabled      bool            `json:"enabled"`
	SavedBy      *uuid.UUID      `json:"saved_by"`
	SavedAt      time.Time       `json:"saved_at"`
}

// Versions returns the last 200 saves of one of the organization's policies, newest
// first.
func (s *Service) Versions(ctx context.Context, id, organizationID uuid.UUID) ([]PolicyVersion, error) {
	if _, err := s.Get(ctx, id, organizationID); err != nil {
		return nil, err
	}
	rows, err := s.q.ListAbacPolicyVersions(ctx, dbgen.ListAbacPolicyVersionsParams{PolicyID: id, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	out := make([]PolicyVersion, 0, len(rows))
	for _, r := range rows {
		out = append(out, toVersion(dbgen.GetAbacPolicyVersionRow(r)))
	}
	return out, nil
}

func toVersion(r dbgen.GetAbacPolicyVersionRow) PolicyVersion {
	v := PolicyVersion{
		Version: int(r.Version), Name: r.Name, Description: r.Description, Effect: r.Effect,
		ResourceType: r.ResourceType, Action: r.Action, Condition: json.RawMessage(r.Condition),
		Priority: int(r.Priority), Enabled: r.Enabled, SavedAt: r.SavedAt,
	}
	v.SavedBy = r.SavedBy
	return v
}

// Restore saves one of a policy's earlier versions as its next, checked as any
// change is, and recorded as abac_policy.restored.
func (s *Service) Restore(ctx context.Context, id, organizationID uuid.UUID, version int, actor audit.Actor) (*Policy, error) {
	row, err := s.q.GetAbacPolicyVersion(ctx, dbgen.GetAbacPolicyVersionParams{
		PolicyID: id, OrganizationID: organizationID, Version: int32(version), // #nosec G115 -- a version number from the path, compared only
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v := toVersion(row)
	return s.update(ctx, id, organizationID, UpdateInput{
		Name: v.Name, Description: v.Description, Effect: v.Effect, ResourceType: v.ResourceType,
		Action: v.Action, Condition: v.Condition, Priority: v.Priority, Enabled: v.Enabled,
	}, actor, version)
}
