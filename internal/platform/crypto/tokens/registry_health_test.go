package tokens

import (
	"context"
	"errors"
	"testing"
)

// TestReadyFollowsRefreshesInARow checks that Ready fails only after
// SyncFailuresUntilNotReady failed refreshes in a row, and recovers on a success.
func TestReadyFollowsRefreshesInARow(t *testing.T) {
	r := &SigningKeyRegistry{}
	ctx := context.Background()
	boom := errors.New("can't open the active key")
	for i := 1; i < SyncFailuresUntilNotReady; i++ {
		r.recordSync("kid-a", boom)
		if err := r.Ready(ctx); err != nil {
			t.Fatalf("not ready after %d failure(s): %v", i, err)
		}
	}
	r.recordSync("kid-a", boom)
	if err := r.Ready(ctx); !errors.Is(err, boom) {
		t.Fatalf("after %d failures in a row: Ready = %v, want it to wrap the last failure", SyncFailuresUntilNotReady, err)
	}
	r.recordSync("kid-a", nil)
	if err := r.Ready(ctx); err != nil {
		t.Fatalf("a successful refresh didn't make it ready again: %v", err)
	}
	r.recordSync("kid-a", boom)
	if err := r.Ready(ctx); err != nil {
		t.Fatalf("one failure after a success made it not ready: %v", err)
	}
}
