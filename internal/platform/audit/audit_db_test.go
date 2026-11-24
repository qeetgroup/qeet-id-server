//go:build integration

package audit

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

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
