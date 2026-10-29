//go:build integration

package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// onShard makes Record put platform events on shard until t ends.
func onShard(t *testing.T, shard int16) {
	t.Helper()
	orig := platformShard
	platformShard = func(pgx.Tx) int16 { return shard }
	t.Cleanup(func() { platformShard = orig })
}

// recordPlatform writes one platform event on shard, committed, and returns
// its id.
func recordPlatform(t *testing.T, shard int16, action string) uuid.UUID {
	t.Helper()
	onShard(t, shard)
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := Record(ctx, tx, Actor{Type: "system"}.PlatformEvent(action, "user", uuid.New(), nil)); err != nil {
		t.Fatalf("record %s on chain %d: %v", action, shard, err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit.events WHERE tenant_id IS NULL AND chain_shard = $1
		ORDER BY created_at DESC, id DESC LIMIT 1`, shard).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

// inTx runs fn in a transaction that is rolled back after, with a Verifier
// that reads through it, so a test can tamper with the platform chains, which
// every test shares, without leaving them broken.
func inTx(t *testing.T, fn func(tx pgx.Tx, v *Verifier)) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	fn(tx, &Verifier{q: dbgen.New(tx)})
}

// TestPlatformShardFollowsTheConnection checks that a transaction's platform
// events all go on its connection's chain.
func TestPlatformShardFollowsTheConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var pid int64
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if got, want := platformShard(tx), int16(pid%PlatformChainShards); got != want {
		t.Errorf("platform chain %d for backend %d, want %d", got, pid, want)
	}
}

// TestPlatformChainsDontWaitForEachOther checks that a transaction writing to
// one platform chain doesn't hold up a writer on another, while a second
// writer on the same chain waits for the first.
func TestPlatformChainsDontWaitForEachOther(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	begin := func() pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		// A writer that would wait gives up quickly instead.
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	write := func(tx pgx.Tx, shard int16) error {
		onShard(t, shard)
		return Record(ctx, tx, Actor{Type: "system"}.PlatformEvent("auth.signed_up", "user", uuid.New(), nil))
	}

	first := begin()
	if err := write(first, 1); err != nil {
		t.Fatalf("first writer on chain 1: %v", err)
	}
	other := begin()
	if err := write(other, 2); err != nil {
		t.Errorf("a writer on chain 2 while chain 1 is held: %v, want no wait", err)
	}
	same := begin()
	var pgErr *pgconn.PgError
	if err := write(same, 1); !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("a second writer on chain 1 while it is held: %v, want it to wait (lock_not_available)", err)
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestPlatformChainsVerify checks that every platform chain verifies on its
// own, that a changed or moved row is found on its chain, that a row written
// as the single platform chain wrote it still verifies on chain 0, and that a
// chain with no row, or a row on no chain, is reported.
func TestPlatformChainsVerify(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if err := OpenPlatformChains(ctx, pool); err != nil {
		t.Fatalf("open the platform chains: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(DISTINCT chain_shard) FROM audit.events WHERE tenant_id IS NULL`); n != PlatformChainShards {
		t.Fatalf("%d platform chains have a row, want %d", n, PlatformChainShards)
	}
	if err := OpenPlatformChains(ctx, pool); err != nil {
		t.Fatalf("open the platform chains again: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id IS NULL AND action = 'audit.chain_opened'`); n > PlatformChainShards {
		t.Errorf("opening the chains twice wrote %d chain_opened rows, want at most %d", n, PlatformChainShards)
	}
	recordPlatform(t, 3, "auth.signed_up")
	changed := recordPlatform(t, 3, "auth.login_succeeded")
	recordPlatform(t, 3, "auth.logout")
	moved := recordPlatform(t, 4, "auth.signed_up")
	recordPlatform(t, 4, "auth.logout")
	legacy := writeAsTheSinglePlatformChain(t)

	res, err := NewVerifier(pool).Verify(ctx, nil)
	if err != nil || !res.OK || res.RowsChecked < PlatformChainShards+5 {
		t.Fatalf("verify the platform chains: %+v, %v; want every row intact", res, err)
	}
	for shard, want := range map[int16]int{0: 1, 3: 3, 4: 2} {
		res, _, err := NewVerifier(pool).walk(ctx, nil, shard, nil, true)
		if err != nil || !res.OK || res.RowsChecked < want {
			t.Errorf("verify chain %d alone: %+v, %v; want at least %d rows intact", shard, res, err, want)
		}
	}
	if res, _, err := NewVerifier(pool).walk(ctx, nil, 0, nil, true); err != nil || !res.OK || *res.LastVerifiedID != legacy {
		t.Errorf("chain 0 with a row written the old way: %+v, %v; want it intact to %s", res, err, legacy)
	}

	inTx(t, func(tx pgx.Tx, v *Verifier) {
		if _, err := tx.Exec(ctx, `UPDATE audit.events SET action = 'auth.deleted' WHERE id = $1 AND tenant_id IS NULL`, changed); err != nil {
			t.Fatal(err)
		}
		res, err := v.Verify(ctx, nil)
		if err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != changed || res.ReasonCode != ChainRowHashMismatch {
			t.Errorf("verify with a changed row on chain 3: %+v, %v; want broken at %s", res, err, changed)
		}
	})
	inTx(t, func(tx pgx.Tx, v *Verifier) {
		if _, err := tx.Exec(ctx, `UPDATE audit.events SET chain_shard = 5 WHERE id = $1 AND tenant_id IS NULL`, moved); err != nil {
			t.Fatal(err)
		}
		res, _, err := v.walk(ctx, nil, 4, nil, true)
		if err != nil || res.OK {
			t.Errorf("chain 4 without its first row: %+v, %v; want broken", res, err)
		}
		res, _, err = v.walk(ctx, nil, 5, nil, true)
		if err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != moved {
			t.Errorf("chain 5 with a row moved onto it: %+v, %v; want broken at %s", res, err, moved)
		}
	})
	inTx(t, func(tx pgx.Tx, v *Verifier) {
		if _, err := tx.Exec(ctx, `DELETE FROM audit.events WHERE tenant_id IS NULL AND chain_shard = 9`); err != nil {
			t.Fatal(err)
		}
		res, err := v.Verify(ctx, nil)
		if err != nil || res.OK || res.ReasonCode != chainShardMissing || !strings.Contains(res.BrokenReason, "9") {
			t.Errorf("verify with chain 9 emptied: %+v, %v; want %s naming chain 9", res, err, chainShardMissing)
		}
	})
	inTx(t, func(tx pgx.Tx, v *Verifier) {
		stray := recordPlatform(t, 6, "auth.signed_up")
		if _, err := tx.Exec(ctx, `UPDATE audit.events SET chain_shard = $2 WHERE id = $1 AND tenant_id IS NULL`, stray, PlatformChainShards); err != nil {
			t.Fatal(err)
		}
		res, err := v.Verify(ctx, nil)
		if err != nil || res.OK || res.ReasonCode != chainShardOutOfRange || res.BrokenAtID == nil || *res.BrokenAtID != stray {
			t.Errorf("verify with a row on chain %d: %+v, %v; want %s at %s", PlatformChainShards, res, err, chainShardOutOfRange, stray)
		}
		run, err := v.verifyAll(ctx, true)
		if !errors.Is(err, ErrChainBroken) || len(run.Broken) == 0 || *run.Broken[len(run.Broken)-1].EventID != stray {
			t.Errorf("scheduled run with a row on no chain: %+v, %v; want it reported", run.Broken, err)
		}
	})
	if res, err := NewVerifier(pool).Verify(ctx, nil); err != nil || !res.OK {
		t.Errorf("verify once the tampering is rolled back: %+v, %v; want intact", res, err)
	}
}

// writeAsTheSinglePlatformChain writes a platform row as the release before
// the platform chains wrote one: chained to chain 0's tip and hashed without a
// shard, the insert naming no chain_shard. It returns its id.
func writeAsTheSinglePlatformChain(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := lockChain(ctx, tx, nil, 0); err != nil {
		t.Fatal(err)
	}
	var prev string
	var tipAt time.Time
	if err := tx.QueryRow(ctx, `SELECT row_hash, created_at FROM audit.events WHERE tenant_id IS NULL AND chain_shard = 0
		AND row_hash IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&prev, &tipAt); err != nil {
		t.Fatal(err)
	}
	e := Event{ActorType: "system", Action: "auth.signed_up", ResourceType: "user"}
	id, at, meta := uuid.New(), tipAt.Add(time.Millisecond), []byte("{}")
	raw, err := canonicalize(e, 0, id, at, meta, strings.TrimSpace(prev))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "chain_shard") {
		t.Fatalf("a chain 0 row's hashed form names its chain: %s", raw)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit.events (id, actor_type, action, resource_type, metadata, created_at, prev_hash, row_hash, user_agent, request_id)
		VALUES ($1, 'system', 'auth.signed_up', 'user', '{}', $2, $3, $4, '', '')`,
		id, at, strings.TrimSpace(prev), hashHex(raw)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestEachPlatformChainKeepsItsCheckpoint checks that a scheduled run keeps a
// checkpoint per platform chain, at that chain's last row, moves on only the
// chain that grew, and keeps one per chain however many runs write one.
func TestEachPlatformChainKeepsItsCheckpoint(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if err := OpenPlatformChains(ctx, pool); err != nil {
		t.Fatal(err)
	}
	last10 := recordPlatform(t, 10, "auth.signed_up")
	last11 := recordPlatform(t, 11, "auth.signed_up")
	verifyAllOf(t, false)
	at := func(shard int16) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT event_id FROM platform.audit_chain_checkpoints
			WHERE tenant_id IS NULL AND chain_shard = $1`, shard).Scan(&id); err != nil {
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
	v := NewVerifier(pool)
	for range 2 {
		if err := v.keepCheckpoint(ctx, chain{shard: 10}, nil, &checkpoint{EventID: uuid.New(), CreatedAt: time.Now(), RowHash: chainSeed}, true); err != nil {
			t.Fatalf("a second first checkpoint of chain 10: %v", err)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.audit_chain_checkpoints WHERE tenant_id IS NULL AND chain_shard = 10`); n != 1 {
		t.Errorf("chain 10 has %d checkpoints, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.audit_chain_checkpoints WHERE tenant_id IS NULL`); n != PlatformChainShards {
		t.Errorf("%d platform checkpoints, want one per chain, %d", n, PlatformChainShards)
	}
}
