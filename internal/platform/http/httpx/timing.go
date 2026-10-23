package httpx

import (
	"context"
	"time"
)

// ConstantTimeFloor blocks until at least floor has passed since start, or ctx
// is done, so an enumeration-sensitive endpoint (signup, recovery) takes as long
// to say "no account" as to succeed. Pick a floor just above the slowest
// legitimate path.
func ConstantTimeFloor(ctx context.Context, start time.Time, floor time.Duration) {
	remaining := floor - time.Since(start)
	if remaining <= 0 {
		return
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
