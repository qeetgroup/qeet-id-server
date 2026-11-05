package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Monthly active users are the people active in an organisation in a calendar
// month (UTC): a person who signs in to it, or renews a session in it, at least
// once that month counts once. The plans' allowances are in these units. API
// keys, service principals and AI agents are not people, and their tokens are
// never recorded.

// execer runs a statement: a pool, or a transaction to record in step with the
// sign-in or renewal it belongs to.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RecordActive marks userID active in tenantID this month. Run it in the
// sign-in's or renewal's own transaction, so a refused one doesn't count. A
// person already counted this month is left as they are. A tenant-less session
// belongs to no organisation and is not recorded.
func RecordActive(ctx context.Context, db execer, tenantID, userID uuid.UUID) error {
	if tenantID == uuid.Nil || userID == uuid.Nil {
		return nil
	}
	_, err := db.Exec(ctx, `INSERT INTO tenant.monthly_active_users (tenant_id, month, user_id)
		VALUES ($1, date_trunc('month', NOW() AT TIME ZONE 'UTC')::date, $2)
		ON CONFLICT (tenant_id, month, user_id) DO NOTHING`, tenantID, userID)
	return err
}

// CountMonthlyActive is how many people have been active in tenantID so far
// this calendar month (UTC).
func (r *Repository) CountMonthlyActive(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM tenant.monthly_active_users
		WHERE tenant_id = $1 AND month = date_trunc('month', NOW() AT TIME ZONE 'UTC')::date`, tenantID).Scan(&n)
	return n, err
}
