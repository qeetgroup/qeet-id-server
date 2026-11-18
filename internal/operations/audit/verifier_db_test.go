//go:build integration

package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPlatformChainsVerify checks that every platform chain verifies on its
// own, that a changed or moved row is found on its chain, that a row written
// as the single platform chain wrote it still verifies on chain 0, and that a
// chain with no row, or a row on no chain, is reported.
func TestPlatformChainsVerify(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if err := OpenPlatformChains(ctx, pool); err != nil {
		t.Fatalf("open the platform chains: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(DISTINCT chain_shard) FROM audit.events WHERE organization_id IS NULL`); n != PlatformChainShards {
		t.Fatalf("%d platform chains have a row, want %d", n, PlatformChainShards)
	}
	if err := OpenPlatformChains(ctx, pool); err != nil {
		t.Fatalf("open the platform chains again: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id IS NULL AND action = 'audit.chain_opened'`); n > PlatformChainShards {
		t.Errorf("opening the chains twice wrote %d chain_opened rows, want at most %d", n, PlatformChainShards)
	}
	recordPlatform(t, 3, "auth.signed_up")
	changed := recordPlatform(t, 3, "auth.login_succeeded")
	recordPlatform(t, 3, "auth.logout")
	moved := recordPlatform(t, 4, "auth.signed_up")
	recordPlatform(t, 4, "auth.logout")
	legacy := writeAsTheSinglePlatformChain(t)

	res, err := NewVerifier(pool, nil).Verify(ctx, nil)
	if err != nil || !res.OK || res.RowsChecked < PlatformChainShards+5 {
		t.Fatalf("verify the platform chains: %+v, %v; want every row intact", res, err)
	}
	for shard, want := range map[int16]int{0: 1, 3: 3, 4: 2} {
		res, _, err := NewVerifier(pool, nil).walk(ctx, nil, shard, nil, true)
		if err != nil || !res.OK || res.RowsChecked < want {
			t.Errorf("verify chain %d alone: %+v, %v; want at least %d rows intact", shard, res, err, want)
		}
	}
	if res, _, err := NewVerifier(pool, nil).walk(ctx, nil, 0, nil, true); err != nil || !res.OK || *res.LastVerifiedID != legacy {
		t.Errorf("chain 0 with a row written the old way: %+v, %v; want it intact to %s", res, err, legacy)
	}

	inTx(t, func(tx pgx.Tx, v *Verifier) {
		if _, err := tx.Exec(ctx, `UPDATE audit.events SET action = 'auth.deleted' WHERE id = $1 AND organization_id IS NULL`, changed); err != nil {
			t.Fatal(err)
		}
		res, err := v.Verify(ctx, nil)
		if err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != changed || res.ReasonCode != ChainRowHashMismatch {
			t.Errorf("verify with a changed row on chain 3: %+v, %v; want broken at %s", res, err, changed)
		}
	})
	inTx(t, func(tx pgx.Tx, v *Verifier) {
		if _, err := tx.Exec(ctx, `UPDATE audit.events SET chain_shard = 5 WHERE id = $1 AND organization_id IS NULL`, moved); err != nil {
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
		if _, err := tx.Exec(ctx, `DELETE FROM audit.events WHERE organization_id IS NULL AND chain_shard = 9`); err != nil {
			t.Fatal(err)
		}
		res, err := v.Verify(ctx, nil)
		if err != nil || res.OK || res.ReasonCode != chainShardMissing || !strings.Contains(res.BrokenReason, "9") {
			t.Errorf("verify with chain 9 emptied: %+v, %v; want %s naming chain 9", res, err, chainShardMissing)
		}
	})
	inTx(t, func(tx pgx.Tx, v *Verifier) {
		stray := recordPlatform(t, 6, "auth.signed_up")
		if _, err := tx.Exec(ctx, `UPDATE audit.events SET chain_shard = $2 WHERE id = $1 AND organization_id IS NULL`, stray, PlatformChainShards); err != nil {
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
	if res, err := NewVerifier(pool, nil).Verify(ctx, nil); err != nil || !res.OK {
		t.Errorf("verify once the tampering is rolled back: %+v, %v; want intact", res, err)
	}
}
