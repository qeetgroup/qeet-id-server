package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// purgeBatch is how many events one purge transaction deletes from a chain.
var purgeBatch int32 = 1000

// PurgeExpired deletes each organization's audit events older than the days
// days returns for it (less than one: kept for good), oldest first and a
// batch at a time, and records each organization's purge on its chain. It
// returns how many it deleted. key signs each purge checkpoint. A lookup or
// purge that fails skips its organization and is returned with the others' errors.
func PurgeExpired(ctx context.Context, pool *pgxpool.Pool, key CheckpointKey, days func(ctx context.Context, organizationID uuid.UUID) (int, error)) (int64, error) {
	ctx = postgres.AcrossOrganizations(ctx)
	organizations, err := dbgen.New(pool).ListRetentionOrganizations(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	var failed []error
	for _, organizationID := range organizations {
		keep, err := days(ctx, organizationID)
		if err != nil {
			failed = append(failed, fmt.Errorf("organization %s: %w", organizationID, err))
			continue
		}
		if keep < 1 {
			continue
		}
		n, err := purgeChain(ctx, pool, key, organizationID, time.Now().Add(-time.Duration(keep)*24*time.Hour))
		total += n
		if err == nil && n > 0 {
			err = recordPurge(ctx, pool, organizationID, n, keep)
		}
		if err != nil {
			failed = append(failed, fmt.Errorf("organization %s: %w", organizationID, err))
		}
	}
	return total, errors.Join(failed...)
}

// purgeChain deletes organizationID's events sent before cutoff, never the chain's
// newest, and returns how many. Each batch is deleted in the transaction that
// moves the chain's purge checkpoint to the last event it deletes, holding the
// chain's lock, so the chain verifies from there at every moment. A chain the
// scheduled verification found broken is left for whoever investigates it.
func purgeChain(ctx context.Context, pool *pgxpool.Pool, key CheckpointKey, organizationID uuid.UUID, cutoff time.Time) (int64, error) {
	if broken, err := dbgen.New(pool).AuditChainBroken(ctx, organizationID); err != nil || broken {
		return 0, err
	}
	var total int64
	for {
		n, err := purgeBatchOf(ctx, pool, key, organizationID, cutoff)
		total += n
		if err != nil || n < int64(purgeBatch) {
			return total, err
		}
	}
}

// purgeBatchOf deletes one batch of purgeChain's events, returning how many.
func purgeBatchOf(ctx context.Context, pool *pgxpool.Pool, key CheckpointKey, organizationID uuid.UUID, cutoff time.Time) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err := lockChain(ctx, tx, &organizationID, 0); err != nil {
		return 0, err
	}
	q := dbgen.New(tx)
	rows, err := q.ListAuditEventsToPurge(ctx, dbgen.ListAuditEventsToPurgeParams{OrganizationID: organizationID, Cutoff: cutoff, Batch: purgeBatch})
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	last := rows[len(rows)-1]
	start := &checkpoint{EventID: last.ID, CreatedAt: last.CreatedAt, RowHash: strings.TrimSpace(*last.RowHash)}
	keyID, mac := signCheckpoint(key, purgeCheckpointKind, &organizationID, 0, start)
	if err := q.SetAuditPurgeCheckpoint(ctx, dbgen.SetAuditPurgeCheckpointParams{
		OrganizationID: organizationID, EventID: start.EventID, EventCreatedAt: start.CreatedAt,
		RowHash: start.RowHash, Purged: int64(len(rows)), KeyID: keyID, Mac: mac,
	}); err != nil {
		return 0, err
	}
	if _, err := q.DeleteAuditEventsThrough(ctx, dbgen.DeleteAuditEventsThroughParams{
		OrganizationID: organizationID, CreatedAt: last.CreatedAt, ID: last.ID,
	}); err != nil {
		return 0, err
	}
	return int64(len(rows)), tx.Commit(ctx)
}

// recordPurge records on organizationID's chain that deleted of its events, older
// than days, were removed.
func recordPurge(ctx context.Context, pool *pgxpool.Pool, organizationID uuid.UUID, deleted int64, days int) error {
	return RecordAlone(ctx, pool, Actor{Type: "system"}.Event(organizationID, "audit.events_purged", "organization", organizationID,
		map[string]any{"deleted": deleted, "days": days}))
}
