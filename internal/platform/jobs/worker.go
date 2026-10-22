// Package worker runs a set of named background workers with coordinated
// startup and graceful shutdown, so adding a worker is one Register call
// instead of hand-managing a WaitGroup.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// Func is a long-running worker. It must return promptly once ctx is cancelled.
type Func func(ctx context.Context)

// Supervisor owns a named set of workers.
type Supervisor struct {
	mu      sync.Mutex
	workers []named
}

type named struct {
	name string
	fn   Func
}

// New returns a Supervisor with no workers.
func New() *Supervisor { return &Supervisor{} }

// Register adds a named worker to be launched by Start.
func (s *Supervisor) Register(name string, fn Func) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workers = append(s.workers, named{name: name, fn: fn})
}

// Restart backoff bounds. A worker that panics is restarted after a delay that
// doubles up to restartBackoffMax, so a deterministic panic cannot hot-loop.
// A worker that stays up for longer than restartResetAfter is considered
// healthy again and its backoff resets.
const (
	restartBackoffMin = time.Second
	restartBackoffMax = time.Minute
	restartResetAfter = 5 * time.Minute
)

// Start launches every registered worker with ctx and returns a func that waits
// for all of them to return (call it after cancelling ctx). A worker that panics
// is recovered and restarted with backoff, so one bad row can't take down the
// process.
func (s *Supervisor) Start(ctx context.Context) (wait func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var wg sync.WaitGroup
	for _, w := range s.workers {
		wg.Add(1)
		go func(w named) {
			defer wg.Done()
			s.supervise(ctx, w)
		}(w)
	}
	return wg.Wait
}

// supervise runs one worker, restarting it with capped exponential backoff if it
// panics. It returns when ctx is cancelled or the worker returns normally
// (workers are expected to return promptly on cancellation).
func (s *Supervisor) supervise(ctx context.Context, w named) {
	backoff := restartBackoffMin
	for {
		startedAt := time.Now()
		panicked := s.runOnce(ctx, w)
		if !panicked {
			slog.Info("worker stopped", "name", w.name)
			return
		}
		if ctx.Err() != nil {
			// Shutting down anyway — do not restart.
			return
		}
		if time.Since(startedAt) >= restartResetAfter {
			backoff = restartBackoffMin
		}
		slog.Error("worker restarting after panic", "name", w.name, "in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > restartBackoffMax {
			backoff = restartBackoffMax
		}
	}
}

// runOnce invokes the worker, converting a panic into a logged event and a
// `true` return rather than letting it unwind into the process.
func (s *Supervisor) runOnce(ctx context.Context, w named) (panicked bool) {
	defer func() {
		if rec := recover(); rec != nil {
			panicked = true
			// The stack is the only way to find the offending line; a worker
			// panic leaves no request context behind.
			slog.Error("worker panic recovered",
				"name", w.name,
				"panic", fmt.Sprint(rec),
				"stack", string(debug.Stack()),
			)
		}
	}()
	w.fn(ctx)
	return false
}
