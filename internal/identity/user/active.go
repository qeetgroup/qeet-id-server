package user

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/user/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// Monthly active users are the people active in an organization in a calendar month (UTC): signing
// in to it or renewing a session in it at least once that month counts once. The plans' allowances
// are in these units. API keys, service principals and AI agents are not people and never counted.

// RecordActive marks userID active in organizationID this month. Run it in the
// sign-in's or renewal's own transaction, so a refused one doesn't count. A
// person already counted this month is left as they are. An organization-less session
// belongs to no organization and is not recorded.
func RecordActive(ctx context.Context, db postgres.Querier, organizationID, userID uuid.UUID) error {
	if organizationID == uuid.Nil || userID == uuid.Nil {
		return nil
	}
	return dbgen.New(db).RecordMonthlyActive(ctx, dbgen.RecordMonthlyActiveParams{OrganizationID: organizationID, UserID: userID})
}

// CountMonthlyActive is how many people have been active in organizationID so far
// this calendar month (UTC).
func (r *Repository) CountMonthlyActive(ctx context.Context, organizationID uuid.UUID) (int, error) {
	n, err := r.q.CountMonthlyActive(ctx, organizationID)
	return int(n), err
}
