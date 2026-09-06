package worker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestSupervisorRecoversWorkerPanic is the regression test for the availability
// bug: a panic in any single background worker used to unwind past the
// supervisor goroutine and terminate the whole process — HTTP server, in-flight
// requests and all six sibling workers with it.
//
// The test asserts three things: the panic does not propagate, the sibling
// worker keeps running, and the wait func still returns on cancellation.
func TestSupervisorRecoversWorkerPanic(t *testing.T) {
	s := New()

	var panics atomic.Int32
	s.Register("panicker", func(ctx context.Context) {
		panics.Add(1)
		panic("boom: simulated bad row")
	})

	siblingRan := make(chan struct{})
	var siblingStopped atomic.Bool
	s.Register("sibling", func(ctx context.Context) {
		close(siblingRan)
		<-ctx.Done()
		siblingStopped.Store(true)
	})

	ctx, cancel := context.WithCancel(context.Background())
	wait := s.Start(ctx)

	select {
	case <-siblingRan:
	case <-time.After(2 * time.Second):
		t.Fatal("sibling worker never started — the panic took the process path")
	}

	// The panicking worker is restarted with backoff, so it must have run at
	// least once and the supervisor must still be alive.
	if got := panics.Load(); got < 1 {
		t.Fatalf("panicking worker ran %d times, want >= 1", got)
	}

	cancel()
	done := make(chan struct{})
	go func() { wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait() did not return after cancellation")
	}
	if !siblingStopped.Load() {
		t.Error("sibling worker did not observe cancellation")
	}
}

// TestSupervisorDoesNotRestartAfterCancel pins that a panic racing with
// shutdown does not spin: once ctx is cancelled the worker is not relaunched.
func TestSupervisorDoesNotRestartAfterCancel(t *testing.T) {
	s := New()
	var runs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	s.Register("panic-on-shutdown", func(ctx context.Context) {
		runs.Add(1)
		cancel()
		panic("panic during shutdown")
	})

	wait := s.Start(ctx)
	done := make(chan struct{})
	go func() { wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor kept restarting a worker after cancellation")
	}
	if got := runs.Load(); got != 1 {
		t.Errorf("worker ran %d times after cancel, want 1", got)
	}
}
