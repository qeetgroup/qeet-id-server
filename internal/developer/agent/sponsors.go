package agent

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/developer/agent/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
)

// sponsorBelongsToOrganization reports whether userID is a member of organizationID: a
// sponsor must be an accountable member of the organization, not just any user.
func (s *Service) sponsorBelongsToOrganization(ctx context.Context, organizationID, userID uuid.UUID) (bool, error) {
	return s.q.SponsorBelongsToOrganization(ctx, dbgen.SponsorBelongsToOrganizationParams{
		UserID:         userID,
		OrganizationID: organizationID,
	})
}

// AgentsSponsoredBy lists an organization's (non-decommissioned) agents sponsored by
// userID — what an admin needs to see before offboarding that person, so no
// agent is left with an owner who no longer has access.
func (s *Service) AgentsSponsoredBy(ctx context.Context, organizationID, userID uuid.UUID) ([]Agent, error) {
	rows, err := s.q.ListAgentsSponsoredBy(ctx, dbgen.ListAgentsSponsoredByParams{
		OrganizationID: organizationID,
		UserID:         &userID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, row := range rows {
		out = append(out, Agent{
			ID:              row.ID,
			Name:            row.Name,
			Scopes:          row.Scopes,
			TokenTTLSeconds: int(row.TokenTtlSeconds),
			Status:          row.Status,
			Disabled:        row.Status != "active",
			SponsorUserID:   row.SponsorUserID,
			CreatedAt:       row.CreatedAt,
		})
	}
	return out, nil
}

// TransferSponsor reassigns, in one statement, every agent fromUserID sponsors
// in organizationID to toUserID, who must be an organization member, and returns how many
// moved. Run it before removing fromUserID's access when offboarding.
func (s *Service) TransferSponsor(ctx context.Context, organizationID, fromUserID, toUserID uuid.UUID, actor audit.Actor) (int, error) {
	if toUserID == uuid.Nil {
		return 0, ErrSponsorRequired
	}
	if ok, err := s.sponsorBelongsToOrganization(ctx, organizationID, toUserID); err != nil {
		return 0, err
	} else if !ok {
		return 0, ErrSponsorNotMember
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).TransferAgentSponsor(ctx, dbgen.TransferAgentSponsorParams{
		ToUserID:       &toUserID,
		OrganizationID: organizationID,
		FromUserID:     &fromUserID,
	})
	if err != nil {
		return 0, err
	}
	count := int(n)
	metadata := map[string]any{"from_user_id": fromUserID, "to_user_id": toUserID, "count": count}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "agent.sponsor_transferred", "user", fromUserID, metadata)); err != nil {
		return 0, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: organizationID, Topic: "agent.events", EventType: "agent.sponsor_transferred",
		Payload: map[string]any{"organization_id": organizationID, "from_user_id": fromUserID, "to_user_id": toUserID, "count": count},
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
