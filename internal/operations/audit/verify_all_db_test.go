//go:build integration

package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// brokenAt is where run found tenant's chain broken, nil when intact. Other
// tests leave broken chains of their own, so only tenant's is looked at.
func brokenAt(t *testing.T, run VerificationRun, tenant uuid.UUID) *uuid.UUID {
	t.Helper()
	for _, b := range run.Broken {
		if b.TenantID != nil && *b.TenantID == tenant {
			return b.EventID
		}
	}
	return nil
}

// verifyAllOf runs a verification from the checkpoints, or from the start, and
// fails t if it couldn't run.
func verifyAllOf(t *testing.T, fromStart bool) VerificationRun {
	t.Helper()
	run, err := NewVerifier(dbtest.Pool(t)).verifyAll(dbtest.Context(t), fromStart)
	if err != nil && !errors.Is(err, ErrChainBroken) {
		t.Fatalf("verify all: %v", err)
	}
	return run
}

// checkpointOf is tenant's checkpoint row and whether it is marked broken.
func checkpointOf(t *testing.T, tenant uuid.UUID) (uuid.UUID, bool) {
	t.Helper()
	var id uuid.UUID
	var broken bool
	err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT event_id, broken_at IS NOT NULL FROM platform.audit_chain_checkpoints WHERE tenant_id = $1`,
		tenant).Scan(&id, &broken)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return id, broken
}

// TestVerifyAllGoesOnFromTheCheckpoint checks that a scheduled run walks a
// chain on from where the last left it, that a run from the start still finds
// a changed old row, and that a chain found broken stays reported.
func TestVerifyAllGoesOnFromTheCheckpoint(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	old := record(t, tenant, "user.created")
	first := record(t, tenant, "user.updated")

	if at := brokenAt(t, verifyAllOf(t, false), tenant); at != nil {
		t.Fatalf("a new chain broken at %s", at)
	}
	if got, _ := checkpointOf(t, tenant); got != first {
		t.Fatalf("checkpoint at %s, want the chain's last row %s", got, first)
	}
	latest := record(t, tenant, "user.deleted")
	if at := brokenAt(t, verifyAllOf(t, false), tenant); at != nil {
		t.Fatalf("a grown chain broken at %s", at)
	}
	if got, _ := checkpointOf(t, tenant); got != latest {
		t.Fatalf("checkpoint at %s, want the new last row %s", got, latest)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.suspended' WHERE id = $1 AND tenant_id = $2`, old, tenant); err != nil {
		t.Fatal(err)
	}
	// A run from the checkpoint reads only the rows after it.
	if at := brokenAt(t, verifyAllOf(t, false), tenant); at != nil {
		t.Errorf("a run from the checkpoint read the row before it, %s", at)
	}
	if at := brokenAt(t, verifyAllOf(t, true), tenant); at == nil || *at != old {
		t.Errorf("a run from the start found the chain broken at %v, want at the changed row %s", at, old)
	}
	if got, broken := checkpointOf(t, tenant); got != latest || !broken {
		t.Errorf("checkpoint at %s, broken %v; want it kept at %s and marked broken", got, broken, latest)
	}
	record(t, tenant, "user.restored")
	if at := brokenAt(t, verifyAllOf(t, false), tenant); at == nil || *at != old {
		t.Errorf("the next run found the chain broken at %v, want at %s again", at, old)
	}
	if got, _ := checkpointOf(t, tenant); got != latest {
		t.Errorf("a broken chain's checkpoint moved to %s, want it kept at %s", got, latest)
	}
}

// TestVerifyAllChecksTheCheckpointRowAgain checks that a run finds the chain
// broken when the row its checkpoint names has changed or gone, the last row
// included, and keeps finding it.
func TestVerifyAllChecksTheCheckpointRowAgain(t *testing.T) {
	ctx := dbtest.Context(t)
	changed, gone := dbtest.Tenant(t), dbtest.Tenant(t)
	record(t, changed, "user.created")
	changedRow := record(t, changed, "user.updated")
	record(t, gone, "user.created")
	goneRow := record(t, gone, "user.updated")
	verifyAllOf(t, false)

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.deleted' WHERE id = $1 AND tenant_id = $2`, changedRow, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM audit.events WHERE id = $1 AND tenant_id = $2`, goneRow, gone); err != nil {
		t.Fatal(err)
	}
	for _, fromStart := range []bool{false, true, false} {
		run := verifyAllOf(t, fromStart)
		if at := brokenAt(t, run, changed); at == nil || *at != changedRow {
			t.Errorf("from the start %v: a changed last row found broken at %v, want %s", fromStart, at, changedRow)
		}
		if at := brokenAt(t, run, gone); at == nil || *at != goneRow {
			t.Errorf("from the start %v: a deleted last row found broken at %v, want %s", fromStart, at, goneRow)
		}
	}
}

// TestVerifyAllWalksFromTheStartWeekly checks that VerifyAll walks every chain
// from the start when no run has within FullVerifyInterval, and from the
// checkpoints otherwise, and stores which it did.
func TestVerifyAllWalksFromTheStartWeekly(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	record(t, dbtest.Tenant(t), "user.created")
	if _, err := pool.Exec(ctx, `
		UPDATE platform.audit_verification_runs SET started_at = started_at - make_interval(secs => $1) WHERE scope = 'all'`,
		(FullVerifyInterval + time.Hour).Seconds()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"all", "incremental"} {
		run, err := NewVerifier(pool).VerifyAll(ctx)
		if err != nil && !errors.Is(err, ErrChainBroken) {
			t.Fatal(err)
		}
		var stored string
		if err := pool.QueryRow(ctx, `SELECT scope FROM platform.audit_verification_runs WHERE id = $1`, run.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if run.Scope != want || stored != want {
			t.Errorf("run scope %q, stored %q; want %q", run.Scope, stored, want)
		}
	}
}

// TestPlatformChainHasOneCheckpoint checks that the platform chain, whose
// tenant_id is NULL, keeps a single checkpoint, however many runs write one.
func TestPlatformChainHasOneCheckpoint(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := Record(ctx, tx, Actor{Type: "system"}.PlatformEvent("platform.tested", "platform", uuid.New(), nil)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	verifyAllOf(t, true)
	v := NewVerifier(pool)
	for range 2 {
		if err := v.keepCheckpoint(ctx, nil, nil, &checkpoint{EventID: uuid.New(), CreatedAt: time.Now(), RowHash: chainSeed}, true); err != nil {
			t.Fatalf("a second first checkpoint of the platform chain: %v", err)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.audit_chain_checkpoints WHERE tenant_id IS NULL`); n != 1 {
		t.Errorf("the platform chain has %d checkpoints, want 1", n)
	}
}
