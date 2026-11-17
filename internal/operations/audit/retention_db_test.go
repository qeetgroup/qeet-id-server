//go:build integration

package audit

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// recordAt writes one audit event for tenant as if at at, and returns its id.
func recordAt(t *testing.T, tenant uuid.UUID, action string, at time.Time) uuid.UUID {
	t.Helper()
	clock = func() time.Time { return at }
	defer func() { clock = time.Now }()
	return record(t, tenant, action)
}

// keeping is a plan lookup keeping each tenant's events the days given, and
// every other tenant's for good.
func keeping(days map[uuid.UUID]int) func(context.Context, uuid.UUID) (int, error) {
	return func(_ context.Context, tenantID uuid.UUID) (int, error) {
		if d, ok := days[tenantID]; ok {
			return d, nil
		}
		return -1, nil
	}
}

// kept reports which of ids are still stored.
func kept(t *testing.T, ids ...uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	rows, err := dbtest.Pool(t).Query(dbtest.Context(t), `SELECT id FROM audit.events WHERE id = ANY($1)`, ids)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out[id] = true
	}
	return out
}

// TestAuditEventsOlderThanThePlanWindowArePurged checks that the events of an
// organisation older than its plan keeps them are deleted, in batches, and the
// rest kept; that the purge is itself recorded; and that a chain the scheduled
// verification found broken is left for whoever investigates it.
func TestAuditEventsOlderThanThePlanWindowArePurged(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	purgeBatch = 2
	t.Cleanup(func() { purgeBatch = 1000 })
	tenant, broken := dbtest.Tenant(t), dbtest.Tenant(t)
	day := 24 * time.Hour
	now := time.Now()
	old := []uuid.UUID{
		recordAt(t, tenant, "user.created", now.Add(-20*day)),
		recordAt(t, tenant, "user.updated", now.Add(-15*day)),
		recordAt(t, tenant, "user.updated", now.Add(-9*day)),
	}
	recent := []uuid.UUID{recordAt(t, tenant, "user.updated", now.Add(-3*day)), record(t, tenant, "user.deleted")}
	brokenOld := recordAt(t, broken, "user.created", now.Add(-20*day))
	record(t, broken, "user.updated")
	if _, err := pool.Exec(ctx, `INSERT INTO platform.audit_chain_checkpoints (tenant_id, event_id, event_created_at, row_hash, broken_at)
		SELECT tenant_id, id, created_at, row_hash, NOW() FROM audit.events WHERE id = $1`, brokenOld); err != nil {
		t.Fatal(err)
	}

	n, err := PurgeExpired(ctx, pool, nil, keeping(map[uuid.UUID]int{tenant: 7, broken: 7}))
	if err != nil || n != int64(len(old)) {
		t.Fatalf("purge: %d, %v; want the %d events older than 7 days", n, err, len(old))
	}
	got := kept(t, append(append(append([]uuid.UUID{}, old...), recent...), brokenOld)...)
	for _, id := range old {
		if got[id] {
			t.Errorf("event %s, older than the plan keeps events, is kept", id)
		}
	}
	for _, id := range recent {
		if !got[id] {
			t.Errorf("event %s, within the plan's window, was deleted", id)
		}
	}
	if !got[brokenOld] {
		t.Error("a chain found broken was purged")
	}
	if c := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'audit.events_purged'
		AND (metadata->>'deleted')::int = $2 AND (metadata->>'days')::int = 7`, tenant, len(old)); c != 1 {
		t.Errorf("the purge was recorded %d times, want once with what it deleted", c)
	}
}

// TestAuditChainStillVerifiesAfterAPurge checks that once old events are
// deleted the chain still verifies, from the start and from a scheduled run's
// checkpoint the purge deleted, and that a change to, or removal of, an event
// it kept is still found.
func TestAuditChainStillVerifiesAfterAPurge(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	day := 24 * time.Hour
	now := time.Now()
	for i := range 4 {
		recordAt(t, tenant, "user.updated", now.Add(-time.Duration(30-i)*day))
	}
	if run := verifyAllOf(t, false); brokenAt(t, run, tenant) != nil {
		t.Fatal("the chain is broken before the purge")
	}
	checkpoint, _ := checkpointOf(t, tenant)
	kept := []uuid.UUID{recordAt(t, tenant, "user.updated", now.Add(-2*day)), record(t, tenant, "user.updated"), record(t, tenant, "user.deleted")}
	if _, err := PurgeExpired(ctx, pool, nil, keeping(map[uuid.UUID]int{tenant: 7})); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE id = $1`, checkpoint); n != 0 {
		t.Fatal("the scheduled run's checkpoint was not among the events purged")
	}

	verifier := NewVerifier(pool, nil)
	if res, err := verifier.Verify(ctx, &tenant); err != nil || !res.OK || res.RowsChecked != len(kept)+1 {
		t.Errorf("verify after the purge: %+v, %v; want the %d events kept, and the purge's record, intact", res, err, len(kept)+1)
	}
	for _, fromStart := range []bool{false, true} {
		if run := verifyAllOf(t, fromStart); brokenAt(t, run, tenant) != nil {
			t.Errorf("a scheduled run (from the start: %v) after the purge found the chain broken", fromStart)
		}
	}

	if _, err := pool.Exec(ctx, `UPDATE audit.events SET action = 'user.created' WHERE id = $1 AND tenant_id = $2`, kept[0], tenant); err != nil {
		t.Fatal(err)
	}
	if res, err := verifier.Verify(ctx, &tenant); err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != kept[0] {
		t.Errorf("verify after a kept event changed: %+v, %v; want broken at %s", res, err, kept[0])
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit.events WHERE id = $1 AND tenant_id = $2`, kept[0], tenant); err != nil {
		t.Fatal(err)
	}
	if res, err := verifier.Verify(ctx, &tenant); err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != kept[1] {
		t.Errorf("verify after a kept event was removed: %+v, %v; want broken at %s", res, err, kept[1])
	}
}

// TestSignedPurgeCheckpointOutlivesAKeyRotation checks that a purge signs the
// checkpoint its chain starts from, and that once the key rotates a scheduled
// run signs it again, so the chain still verifies after the old key is retired.
func TestSignedPurgeCheckpointOutlivesAKeyRotation(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	oldKey, newKey := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	cipher := func(current []byte, previous ...[]byte) *envelope.Cipher {
		t.Helper()
		c, err := envelope.New(current, previous...)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	tenant := dbtest.Tenant(t)
	recordAt(t, tenant, "user.created", time.Now().Add(-30*24*time.Hour))
	record(t, tenant, "user.updated")
	if _, err := PurgeExpired(ctx, pool, cipher(oldKey), keeping(map[uuid.UUID]int{tenant: 7})); err != nil {
		t.Fatal(err)
	}
	for _, v := range []*Verifier{NewVerifier(pool, cipher(oldKey)), NewVerifier(pool, cipher(newKey, oldKey)), NewVerifier(pool, cipher(newKey))} {
		run, err := v.verifyAll(ctx, true)
		if err != nil && !errors.Is(err, ErrChainBroken) {
			t.Fatal(err)
		}
		if at := brokenAt(t, run, tenant); at != nil {
			t.Fatalf("a purged chain found broken at %s", at)
		}
	}
}

// TestUnlimitedPlanKeepsAuditHistory checks that an organisation whose plan
// keeps audit history without limit loses none of it, however old, and that a
// plan lookup that fails deletes nothing.
func TestUnlimitedPlanKeepsAuditHistory(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	unlimited, unknown := dbtest.Tenant(t), dbtest.Tenant(t)
	ancient := []uuid.UUID{
		recordAt(t, unlimited, "user.created", time.Now().Add(-3*365*24*time.Hour)),
		recordAt(t, unknown, "user.created", time.Now().Add(-3*365*24*time.Hour)),
	}
	record(t, unlimited, "user.updated")
	record(t, unknown, "user.updated")
	failing := func(_ context.Context, tenantID uuid.UUID) (int, error) {
		if tenantID == unknown {
			return 0, errors.New("plan store down")
		}
		return -1, nil
	}
	if _, err := PurgeExpired(ctx, pool, nil, failing); err == nil {
		t.Error("a failed plan lookup was not reported")
	}
	if got := kept(t, ancient...); len(got) != len(ancient) {
		t.Errorf("events kept %v, want all of %v", got, ancient)
	}
}
