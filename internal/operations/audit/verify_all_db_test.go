//go:build integration

package audit

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// brokenAt is where run found organization's chain broken, nil when intact. Other
// tests leave broken chains of their own, so only organization's is looked at.
func brokenAt(t *testing.T, run VerificationRun, organization uuid.UUID) *uuid.UUID {
	t.Helper()
	for _, b := range run.Broken {
		if b.OrganizationID != nil && *b.OrganizationID == organization {
			return b.EventID
		}
	}
	return nil
}

// verifyAllOf runs a verification from the checkpoints, or from the start, and
// fails t if it couldn't run.
func verifyAllOf(t *testing.T, fromStart bool) VerificationRun {
	t.Helper()
	run, err := NewVerifier(dbtest.Pool(t), nil).verifyAll(dbtest.Context(t), fromStart)
	if err != nil && !errors.Is(err, ErrChainBroken) {
		t.Fatalf("verify all: %v", err)
	}
	return run
}

// checkpointOf is organization's checkpoint row and whether it is marked broken.
func checkpointOf(t *testing.T, organization uuid.UUID) (uuid.UUID, bool) {
	t.Helper()
	var id uuid.UUID
	var broken bool
	err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT event_id, broken_at IS NOT NULL FROM platform.audit_chain_checkpoints WHERE organization_id = $1`,
		organization).Scan(&id, &broken)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return id, broken
}

// TestEachPlatformChainKeepsItsCheckpoint checks that a scheduled run keeps a
// checkpoint per platform chain, at that chain's last row, moves on only the
// chain that grew, and keeps one per chain however many runs write one.
func TestEachPlatformChainKeepsItsCheckpoint(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if err := audit.OpenPlatformChains(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Other tests here verify with keys of their own, which sign every chain's checkpoint; chains 10
	// and 11 start afresh, so this test reads only the checkpoints its own runs write.
	if _, err := pool.Exec(ctx, `DELETE FROM platform.audit_chain_checkpoints
		WHERE organization_id IS NULL AND chain_shard IN (10, 11)`); err != nil {
		t.Fatal(err)
	}
	last10 := recordPlatform(t, 10, "auth.signed_up")
	last11 := recordPlatform(t, 11, "auth.signed_up")
	verifyAllOf(t, false)
	at := func(shard int16) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT event_id FROM platform.audit_chain_checkpoints
			WHERE organization_id IS NULL AND chain_shard = $1`, shard).Scan(&id); err != nil {
			t.Fatalf("chain %d's checkpoint: %v", shard, err)
		}
		return id
	}
	if at(10) != last10 || at(11) != last11 {
		t.Fatalf("checkpoints at %s and %s, want each chain's last row %s and %s", at(10), at(11), last10, last11)
	}
	grown := recordPlatform(t, 10, "auth.logout")
	verifyAllOf(t, false)
	if at(10) != grown || at(11) != last11 {
		t.Errorf("after chain 10 grew: checkpoints at %s and %s, want %s and %s unmoved", at(10), at(11), grown, last11)
	}
	v := NewVerifier(pool, nil)
	for range 2 {
		if err := v.keepCheckpoint(ctx, chain{shard: 10}, nil, &checkpoint{EventID: uuid.New(), CreatedAt: time.Now(), RowHash: audit.ChainSeed}, true); err != nil {
			t.Fatalf("a second first checkpoint of chain 10: %v", err)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.audit_chain_checkpoints WHERE organization_id IS NULL AND chain_shard = 10`); n != 1 {
		t.Errorf("chain 10 has %d checkpoints, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.audit_chain_checkpoints WHERE organization_id IS NULL`); n != audit.PlatformChainShards {
		t.Errorf("%d platform checkpoints, want one per chain, %d", n, audit.PlatformChainShards)
	}
}

// TestVerifyAllGoesOnFromTheCheckpoint checks that a scheduled run walks a
// chain on from where the last left it, that a run from the start still finds
// a changed old row, and that a chain found broken stays reported.
func TestVerifyAllGoesOnFromTheCheckpoint(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	old := record(t, organization, "user.created")
	first := record(t, organization, "user.updated")

	if at := brokenAt(t, verifyAllOf(t, false), organization); at != nil {
		t.Fatalf("a new chain broken at %s", at)
	}
	if got, _ := checkpointOf(t, organization); got != first {
		t.Fatalf("checkpoint at %s, want the chain's last row %s", got, first)
	}
	latest := record(t, organization, "user.deleted")
	if at := brokenAt(t, verifyAllOf(t, false), organization); at != nil {
		t.Fatalf("a grown chain broken at %s", at)
	}
	if got, _ := checkpointOf(t, organization); got != latest {
		t.Fatalf("checkpoint at %s, want the new last row %s", got, latest)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.suspended' WHERE id = $1 AND organization_id = $2`, old, organization); err != nil {
		t.Fatal(err)
	}
	// A run from the checkpoint reads only the rows after it.
	if at := brokenAt(t, verifyAllOf(t, false), organization); at != nil {
		t.Errorf("a run from the checkpoint read the row before it, %s", at)
	}
	if at := brokenAt(t, verifyAllOf(t, true), organization); at == nil || *at != old {
		t.Errorf("a run from the start found the chain broken at %v, want at the changed row %s", at, old)
	}
	if got, broken := checkpointOf(t, organization); got != latest || !broken {
		t.Errorf("checkpoint at %s, broken %v; want it kept at %s and marked broken", got, broken, latest)
	}
	record(t, organization, "user.restored")
	if at := brokenAt(t, verifyAllOf(t, false), organization); at == nil || *at != old {
		t.Errorf("the next run found the chain broken at %v, want at %s again", at, old)
	}
	if got, _ := checkpointOf(t, organization); got != latest {
		t.Errorf("a broken chain's checkpoint moved to %s, want it kept at %s", got, latest)
	}
}

// TestVerifyAllChecksTheCheckpointRowAgain checks that a run finds the chain
// broken when the row its checkpoint names has changed or gone, the last row
// included, and keeps finding it.
func TestVerifyAllChecksTheCheckpointRowAgain(t *testing.T) {
	ctx := dbtest.Context(t)
	changed, gone := dbtest.Organization(t), dbtest.Organization(t)
	record(t, changed, "user.created")
	changedRow := record(t, changed, "user.updated")
	record(t, gone, "user.created")
	goneRow := record(t, gone, "user.updated")
	verifyAllOf(t, false)

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.deleted' WHERE id = $1 AND organization_id = $2`, changedRow, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM audit.events WHERE id = $1 AND organization_id = $2`, goneRow, gone); err != nil {
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

// rewriteChain changes the action of organization's event id and recomputes the hash
// of it and every later event, and its checkpoint's, as someone who can write
// the tables but doesn't hold the server's key could.
func rewriteChain(t *testing.T, organization, id uuid.UUID) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if _, err := pool.Exec(ctx, `UPDATE audit.events SET action = 'user.restored' WHERE id = $1 AND organization_id = $2`, id, organization); err != nil {
		t.Fatal(err)
	}
	rows, err := dbgen.New(pool).ListAuditEventsForVerify(ctx, dbgen.ListAuditEventsForVerifyParams{
		OrganizationID: &organization, PageSize: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	prev := audit.ChainSeed
	for _, row := range rows {
		row.PrevHash = &prev
		hash, err := rowHash(row)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE audit.events SET prev_hash = $3, row_hash = $4 WHERE id = $1 AND organization_id = $2`,
			row.ID, organization, prev, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE platform.audit_chain_checkpoints SET row_hash = $3 WHERE event_id = $1 AND organization_id = $2`,
			row.ID, organization, hash); err != nil {
			t.Fatal(err)
		}
		prev = hash
	}
}

// TestVerifyAllFindsAChainRewrittenWithItsCheckpoint checks that rewriting an
// old event, every later hash and the chain's checkpoint is found, as only the
// server's key signs a checkpoint, from the checkpoint and from the start, by
// an on-demand verification too; that a forged purge checkpoint is found; and
// that once the key rotates a run signs again, so the old key can be retired.
func TestVerifyAllFindsAChainRewrittenWithItsCheckpoint(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	keyed := func(current []byte, previous ...[]byte) *Verifier {
		t.Helper()
		c, err := envelope.New(current, previous...)
		if err != nil {
			t.Fatal(err)
		}
		return NewVerifier(pool, c)
	}
	oldKey, newKey := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
	walk := func(v *Verifier, fromStart bool, organization uuid.UUID) *uuid.UUID {
		t.Helper()
		run, err := v.verifyAll(ctx, fromStart)
		if err != nil && !errors.Is(err, ErrChainBroken) {
			t.Fatalf("verify all: %v", err)
		}
		return brokenAt(t, run, organization)
	}

	organization := dbtest.Organization(t)
	first := record(t, organization, "user.created")
	record(t, organization, "user.updated")
	if at := walk(keyed(oldKey), false, organization); at != nil {
		t.Fatalf("a new chain broken at %s", at)
	}
	if at := walk(keyed(newKey, oldKey), false, organization); at != nil {
		t.Fatalf("with the key rotated: broken at %s", at)
	}
	retired := keyed(newKey)
	if at := walk(retired, false, organization); at != nil {
		t.Fatalf("with the old key retired after a run: broken at %s", at)
	}

	rewriteChain(t, organization, first)
	for _, fromStart := range []bool{false, true} {
		if at := walk(retired, fromStart, organization); at == nil {
			t.Errorf("from the start %v: a chain rewritten with its checkpoint was found intact", fromStart)
		}
	}
	if res, err := retired.Verify(ctx, &organization); err != nil || res.OK {
		t.Errorf("verify on demand: %+v, %v; want broken", res, err)
	}

	// A purge checkpoint that skips the oldest events must be the server's.
	purged := dbtest.Organization(t)
	skipped := record(t, purged, "user.created")
	record(t, purged, "user.updated")
	if _, err := pool.Exec(ctx, `
		INSERT INTO platform.audit_purge_checkpoints (organization_id, event_id, event_created_at, row_hash)
		SELECT organization_id, id, created_at, row_hash FROM audit.events WHERE id = $1 AND organization_id = $2`, skipped, purged); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit.events WHERE id = $1 AND organization_id = $2`, skipped, purged); err != nil {
		t.Fatal(err)
	}
	if at := walk(retired, true, purged); at == nil || *at != skipped {
		t.Errorf("a chain starting at a forged purge checkpoint: broken at %v, want %s", at, skipped)
	}
}

// TestVerifyAllWalksFromTheStartWeekly checks that VerifyAll walks every chain
// from the start when no run has within FullVerifyInterval, and from the
// checkpoints otherwise, and stores which it did.
func TestVerifyAllWalksFromTheStartWeekly(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	record(t, dbtest.Organization(t), "user.created")
	if _, err := pool.Exec(ctx, `
		UPDATE platform.audit_verification_runs SET started_at = started_at - make_interval(secs => $1) WHERE scope = 'all'`,
		(FullVerifyInterval + time.Hour).Seconds()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"all", "incremental"} {
		run, err := NewVerifier(pool, nil).VerifyAll(ctx)
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

// TestLastVerificationIsRead checks that an organization's last verification
// is read from what the scheduled run stored: nothing before it reaches the
// chain, then when and how far, and a break once found.
func TestLastVerificationIsRead(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Verifier: NewVerifier(pool, nil)}).Mount)
	path := "/organizations/" + organization.String() + "/audit/verification"
	var got ChainVerification
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &got)
	if got.Verified || got.Intact || got.LastVerifiedAt != nil {
		t.Errorf("before any verification: %+v, want not verified", got)
	}

	last := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO platform.audit_chain_checkpoints (organization_id, event_id, event_created_at, row_hash) VALUES ($1, $2, NOW(), $3)`,
		organization, last, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform.audit_chain_checkpoints (organization_id, event_id, event_created_at, row_hash, broken_at) VALUES ($1, $2, NOW(), $3, NOW())`,
		other, uuid.New(), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO platform.audit_verification_runs (id, started_at, finished_at, scope, organizations_walked, rows_checked, outcome) VALUES ($1, NOW(), NOW(), 'incremental', 2, 10, 'broken')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &got)
	if !got.Verified || !got.Intact || got.LastEventID == nil || *got.LastEventID != last || got.LastRunScope != "incremental" || got.LastRunAt == nil {
		t.Errorf("once verified: %+v; want intact up to its last event, and the incremental run, whatever another organization's chain shows", got)
	}
	if _, err := pool.Exec(ctx, `UPDATE platform.audit_chain_checkpoints SET broken_at = NOW() WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &got)
	if got.Intact || got.BrokenAt == nil {
		t.Errorf("once a break is found: %+v, want not intact with when", got)
	}
}
