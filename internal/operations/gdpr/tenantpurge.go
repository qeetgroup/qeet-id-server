package gdpr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// TenantPurgeAfter is how long a deleted organisation's data is kept, so the
// deletion can still be undone, before PurgeDeletedTenants removes it.
const TenantPurgeAfter = 30 * 24 * time.Hour

// tenantPurgesPerRun bounds how many organisations one run purges.
const tenantPurgesPerRun = 10

// tenantPurgeFailures counts organisations a purge run couldn't finish.
var tenantPurgeFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gdpr_tenant_purge_failures_total",
	Help: "Deleted organisations a purge run failed to remove; each is tried again at the next run.",
})

// TenantPurge is what purging one organisation removed.
type TenantPurge struct {
	TenantID         uuid.UUID        `json:"tenant_id"`
	Rows             map[string]int64 `json:"rows_purged"`
	AccountsRemoved  int              `json:"accounts_removed"`
	AccountsDetached int              `json:"accounts_detached"`
}

// PurgeDeletedTenants removes the data of up to tenantPurgesPerRun
// organisations deleted longer ago than after, and returns how many it
// purged. An organisation whose deletion was called off was never deleted, so
// it is never purged. One that fails is logged, counted and tried again next
// run; the others are still purged.
func (s *Service) PurgeDeletedTenants(ctx context.Context, after time.Duration) (int, error) {
	ctx = postgres.AcrossTenants(ctx)
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM tenant.tenants
		WHERE status = 'deleted' AND deleted_at IS NOT NULL AND deleted_at < $1
		ORDER BY deleted_at LIMIT $2`, time.Now().UTC().Add(-after), tenantPurgesPerRun)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, id := range ids {
		if _, err := s.PurgeTenant(ctx, id, after); err != nil {
			tenantPurgeFailures.Inc()
			slog.Warn("gdpr: purge a deleted organisation", "tenant_id", id, "err", err)
			continue
		}
		purged++
	}
	return purged, nil
}

// PurgeTenant removes the data of tenantID, deleted longer ago than after:
// the people whose home it was (erased and removed, or, still members of
// another organisation, kept with no home organisation), then every table's
// rows of it in batches, its audit chain included, then the organisation.
// It records the purge in platform.tenant_purges and the platform audit
// chain, which outlive the data. Interrupted, it carries on at the next run.
func (s *Service) PurgeTenant(ctx context.Context, tenantID uuid.UUID, after time.Duration) (*TenantPurge, error) {
	ctx = postgres.AcrossTenants(ctx)
	var slug string
	var deletedAt time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT slug, deleted_at FROM tenant.tenants
		WHERE id = $1 AND status = 'deleted' AND deleted_at IS NOT NULL AND deleted_at < $2`,
		tenantID, time.Now().UTC().Add(-after)).Scan(&slug, &deletedAt)
	if err != nil {
		return nil, err
	}
	out := &TenantPurge{TenantID: tenantID, Rows: map[string]int64{}}
	if out.AccountsRemoved, out.AccountsDetached, err = s.purgeHomeAccounts(ctx, tenantID); err != nil {
		return nil, err
	}
	if err := s.purgeTenantRows(ctx, tenantID, out.Rows); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// What is left of it holds a foreign key that cascades.
	if _, err := tx.Exec(ctx, `DELETE FROM tenant.tenants WHERE id = $1 AND status = 'deleted'`, tenantID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform.tenant_purges (tenant_id, slug, deleted_at, rows_purged, accounts_removed, accounts_detached)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id) DO UPDATE SET purged_at = NOW(), rows_purged = EXCLUDED.rows_purged,
		    accounts_removed = EXCLUDED.accounts_removed, accounts_detached = EXCLUDED.accounts_detached`,
		tenantID, slug, deletedAt, out.Rows, out.AccountsRemoved, out.AccountsDetached); err != nil {
		return nil, err
	}
	rid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType: "system", Action: "tenant.purged", ResourceType: "tenant", ResourceID: &rid,
		Metadata: map[string]any{"deleted_at": deletedAt, "rows_purged": out.Rows,
			"accounts_removed": out.AccountsRemoved, "accounts_detached": out.AccountsDetached},
	}); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// purgeHomeAccounts erases and removes each account whose home is tenantID,
// and keeps, with no home organisation, one still holding a role in another
// organisation, as their account is that organisation's member too. It
// returns how many it removed and kept.
func (s *Service) purgeHomeAccounts(ctx context.Context, tenantID uuid.UUID) (removed, detached int, err error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id <> $1)
		FROM account.users u WHERE u.tenant_id = $1`, tenantID)
	if err != nil {
		return 0, 0, err
	}
	type account struct {
		id        uuid.UUID
		elsewhere bool
	}
	accounts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (account, error) {
		var a account
		return a, r.Scan(&a.id, &a.elsewhere)
	})
	if err != nil {
		return 0, 0, err
	}
	for _, a := range accounts {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return removed, detached, err
		}
		if a.elsewhere {
			_, err = tx.Exec(ctx, `UPDATE account.users SET tenant_id = NULL WHERE id = $1 AND tenant_id = $2`, a.id, tenantID)
		} else if err = s.eraseAccount(ctx, tx, a.id); err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM account.users WHERE id = $1 AND tenant_id = $2`, a.id, tenantID)
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		_ = tx.Rollback(ctx)
		if err != nil {
			return removed, detached, fmt.Errorf("account %s: %w", a.id, err)
		}
		if a.elsewhere {
			detached++
		} else {
			removed++
		}
	}
	return removed, detached, nil
}

// purgeTenantRows deletes, in batches, tenantID's rows of every table with a
// tenant_id whose foreign key to the organisation doesn't cascade, or that
// has none (the audit log among them), counting each table's in rows. A
// table another one's rows still point at is tried again after the rest.
func (s *Service) purgeTenantRows(ctx context.Context, tenantID uuid.UUID, rows map[string]int64) error {
	list, err := s.pool.Query(ctx, `
		SELECT c.oid::regclass::text
		FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
		WHERE c.relkind = 'r' AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')
		  AND c.oid NOT IN ('tenant.tenants'::regclass, 'platform.tenant_purges'::regclass)
		  AND NOT EXISTS (
		      SELECT 1 FROM pg_constraint k
		      WHERE k.conrelid = c.oid AND k.contype = 'f' AND k.confrelid = 'tenant.tenants'::regclass
		        AND k.confdeltype = 'c' AND k.conkey = ARRAY[a.attnum])
		ORDER BY 1`)
	if err != nil {
		return err
	}
	tables, err := pgx.CollectRows(list, pgx.RowTo[string])
	if err != nil {
		return err
	}
	// A sign-up waiting on the organisation names it in another column.
	if _, err := s.pool.Exec(ctx, `DELETE FROM auth.webauthn_sessions WHERE pending_tenant_id = $1`, tenantID); err != nil {
		return err
	}
	for pass := 0; len(tables) > 0; pass++ {
		var blocked []string
		var lastErr error
		for _, table := range tables {
			// #nosec G201 -- table is a relation name from the catalogue, not input.
			n, err := postgres.PurgeInBatches(ctx, s.pool, fmt.Sprintf(
				`DELETE FROM %s WHERE ctid = ANY(ARRAY(SELECT ctid FROM %s WHERE tenant_id = $1 LIMIT $2))`, table, table), tenantID)
			if n > 0 {
				rows[table] += n
			}
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				blocked, lastErr = append(blocked, table), err
				continue
			}
			if err != nil {
				return fmt.Errorf("%s: %w", table, err)
			}
			// A backlog past one call's batches is finished next run, before
			// the organisation itself goes.
			var left bool
			// #nosec G201 -- table is a relation name from the catalogue, not input.
			if err := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE tenant_id = $1)`, table), tenantID).Scan(&left); err != nil {
				return fmt.Errorf("%s: %w", table, err)
			}
			if left {
				return fmt.Errorf("%s: rows left for the next run", table)
			}
		}
		if len(blocked) == len(tables) || pass > len(tables) {
			return lastErr
		}
		tables = blocked
	}
	return nil
}
