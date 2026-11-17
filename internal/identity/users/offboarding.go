package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/users/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// OffboardTx, in the transaction that deletes userID or removes them from
// tenantID, revokes the admin-portal links and pending invitations they issued
// there and records the critical user.integrations_left event: how many of
// each, and the integrations they created there that still work and need
// review. Every removal calls it. Nothing to list or revoke records nothing.
func (r *Repository) OffboardTx(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, actor audit.Actor) error {
	q := r.q.WithTx(tx)
	links, err := q.RevokeAdminPortalLinksCreatedBy(ctx, dbgen.RevokeAdminPortalLinksCreatedByParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return err
	}
	invites, err := q.RevokeInvitesSentBy(ctx, dbgen.RevokeInvitesSentByParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return err
	}
	rows, err := q.IntegrationsCreatedBy(ctx, dbgen.IntegrationsCreatedByParams{TenantID: tenantID, UserID: userID})
	if err != nil {
		return err
	}
	if len(rows) == 0 && links == 0 && invites == 0 {
		return nil
	}
	integrations := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		integrations = append(integrations, map[string]any{"kind": row.Kind, "id": row.ID, "name": row.Name})
	}
	return audit.Record(ctx, tx, actor.Event(tenantID, "user.integrations_left", "user", userID, map[string]any{
		"integrations":               integrations,
		"admin_portal_links_revoked": links,
		"invitations_revoked":        invites,
	}))
}
