package worker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSupervisorRecoversWorkerPanic checks that a worker panic doesn't escape
// the supervisor, a sibling worker keeps running, and wait still returns once
// ctx is cancelled.
func TestSupervisorRecoversWorkerPanic(t *testing.T) {
	s := New()

	var panics atomic.Int32
	// Signals that the panicking worker has actually run. Each worker is its own
	// goroutine, so the sibling starting tells us nothing about this one — see
	// the wait below.
	panicked := make(chan struct{})
	var signalOnce sync.Once
	s.Register("panicker", func(ctx context.Context) {
		panics.Add(1)
		// Once: the supervisor restarts this worker with backoff, so it runs
		// more than once and closing twice would panic for the wrong reason.
		signalOnce.Do(func() { close(panicked) })
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

	// Wait for the panicking worker itself: the workers are independent
	// goroutines, so under -race the sibling can start before the panicker runs.
	select {
	case <-panicked:
	case <-time.After(2 * time.Second):
		t.Fatal("panicking worker never ran")
	}
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
