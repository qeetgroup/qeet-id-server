package httpx

import (
	"context"
	"time"
)

// ConstantTimeFloor blocks the caller until at least `floor` has
// elapsed since `start`. Used on enumeration-sensitive endpoints
// (signup, recovery) so success and failure paths have indistinguish-
// able latency to a network attacker.
//
// We don't try to floor every endpoint — only the ones where a fast
// "no" leaks the existence of an account (email enumeration). Pick a
// floor a touch higher than the slowest legitimate path; 200–250ms is
// usually right for a signup that does bcrypt + a tx.
//
// Cancellation is honoured: if the request context is cancelled the
// function returns immediately so we don't hold a goroutine on a
// dropped connection.
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
