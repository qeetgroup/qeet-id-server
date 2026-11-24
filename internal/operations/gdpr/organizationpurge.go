package gdpr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// OrganizationPurgeAfter is how long a deleted organization's data is kept, so the
// deletion can still be undone, before PurgeDeletedOrganizations removes it.
const OrganizationPurgeAfter = 30 * 24 * time.Hour

// organizationPurgesPerRun bounds how many organizations one run purges.
const organizationPurgesPerRun = 10

// organizationPurgeFailures counts organizations a purge run couldn't finish.
var organizationPurgeFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gdpr_organization_purge_failures_total",
	Help: "Deleted organizations a purge run failed to remove; each is tried again at the next run.",
})

// OrganizationPurge is what purging one organization removed.
type OrganizationPurge struct {
	OrganizationID   uuid.UUID        `json:"organization_id"`
	Rows             map[string]int64 `json:"rows_purged"`
	AccountsRemoved  int              `json:"accounts_removed"`
	AccountsDetached int              `json:"accounts_detached"`
}

// PurgeDeletedOrganizations removes the data of up to organizationPurgesPerRun organizations deleted
// longer ago than after (a called-off deletion was never one) and returns how many it purged. One that
// fails is logged, counted and retried next run; the others are still purged.
func (s *Service) PurgeDeletedOrganizations(ctx context.Context, after time.Duration) (int, error) {
	ctx = postgres.AcrossOrganizations(ctx)
	ids, err := s.q.ListPurgeableOrganizations(ctx, dbgen.ListPurgeableOrganizationsParams{
		DeletedBefore: time.Now().UTC().Add(-after), MaxRows: organizationPurgesPerRun,
	})
	if err != nil {
		return 0, err
	}
	purged := 0
	for _, id := range ids {
		if _, err := s.PurgeOrganization(ctx, id, after); err != nil {
			organizationPurgeFailures.Inc()
			slog.Warn("gdpr: purge a deleted organization", "organization_id", id, "err", err)
			continue
		}
		purged++
	}
	return purged, nil
}

// PurgeOrganization removes organizationID's data once deleted longer ago than after: its home
// members (erased, or kept homeless when they belong elsewhere), every table's rows in batches, its
// audit chain, then the organization. The purge is recorded in platform.organization_purges and the
// platform chain, which outlive the data; an interrupted purge resumes at the next run.
func (s *Service) PurgeOrganization(ctx context.Context, organizationID uuid.UUID, after time.Duration) (*OrganizationPurge, error) {
	ctx = postgres.AcrossOrganizations(ctx)
	org, err := s.q.GetPurgeableOrganization(ctx, dbgen.GetPurgeableOrganizationParams{
		ID: organizationID, DeletedBefore: time.Now().UTC().Add(-after),
	})
	if err != nil {
		return nil, err
	}
	out := &OrganizationPurge{OrganizationID: organizationID, Rows: map[string]int64{}}
	if out.AccountsRemoved, out.AccountsDetached, err = s.purgeHomeAccounts(ctx, organizationID); err != nil {
		return nil, err
	}
	if err := s.purgeOrganizationRows(ctx, organizationID, out.Rows); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if err := q.DeletePurgedOrganization(ctx, organizationID); err != nil {
		return nil, err
	}
	purged, err := json.Marshal(out.Rows)
	if err != nil {
		return nil, err
	}
	if err := q.RecordOrganizationPurge(ctx, dbgen.RecordOrganizationPurgeParams{
		OrganizationID:   organizationID,
		Slug:             org.Slug,
		DeletedAt:        org.DeletedAt,
		RowsPurged:       purged,
		AccountsRemoved:  int64(out.AccountsRemoved),
		AccountsDetached: int64(out.AccountsDetached),
	}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.PlatformEvent("organization.purged", "organization", organizationID,
		map[string]any{"deleted_at": org.DeletedAt, "rows_purged": out.Rows,
			"accounts_removed": out.AccountsRemoved, "accounts_detached": out.AccountsDetached})); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// purgeHomeAccounts erases and removes each account whose home is organizationID,
// and keeps, with no home organization, one still holding a role in another
// organization, as their account is that organization's member too. It
// returns how many it removed and kept.
func (s *Service) purgeHomeAccounts(ctx context.Context, organizationID uuid.UUID) (removed, detached int, err error) {
	accounts, err := s.q.ListHomeAccounts(ctx, organizationID)
	if err != nil {
		return 0, 0, err
	}
	for _, a := range accounts {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return removed, detached, err
		}
		q := s.q.WithTx(tx)
		if a.Elsewhere {
			err = q.DetachHomeAccount(ctx, dbgen.DetachHomeAccountParams{ID: a.ID, OrganizationID: organizationID})
		} else if err = s.eraseAccount(ctx, tx, a.ID); err == nil {
			err = q.DeleteHomeAccount(ctx, dbgen.DeleteHomeAccountParams{ID: a.ID, OrganizationID: organizationID})
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		_ = tx.Rollback(ctx)
		if err != nil {
			return removed, detached, fmt.Errorf("account %s: %w", a.ID, err)
		}
		if a.Elsewhere {
			detached++
		} else {
			removed++
		}
	}
	return removed, detached, nil
}

// purgeOrganizationRows deletes, in batches, organizationID's rows of every table with an
// organization_id whose foreign key to the organization doesn't cascade, or that
// has none (the audit log among them), counting each table's in rows. A
// table another one's rows still point at is tried again after the rest.
func (s *Service) purgeOrganizationRows(ctx context.Context, organizationID uuid.UUID, rows map[string]int64) error {
	tables, err := s.q.ListOrganizationTables(ctx)
	if err != nil {
		return err
	}
	if err := s.q.DeletePendingSignUps(ctx, &organizationID); err != nil {
		return err
	}
	for pass := 0; len(tables) > 0; pass++ {
		var blocked []string
		var lastErr error
		for _, table := range tables {
			// #nosec G201 -- table is a relation name from the catalogue, not input.
			n, err := postgres.PurgeInBatches(ctx, s.pool, fmt.Sprintf(
				`DELETE FROM %s WHERE ctid = ANY(ARRAY(SELECT ctid FROM %s WHERE organization_id = $1 LIMIT $2))`, table, table), organizationID)
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
			// the organization itself goes.
			var left bool
			// #nosec G201 -- table is a relation name from the catalogue, not input.
			if err := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM %s WHERE organization_id = $1)`, table), organizationID).Scan(&left); err != nil {
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
