// Package worker runs a set of named background workers with coordinated
// startup and graceful shutdown, so adding a worker is one Register call
// instead of hand-managing a WaitGroup.
package worker

import (
	"context"
	"log/slog"
	"sync"
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

func New() *Supervisor { return &Supervisor{} }

// Register adds a named worker to be launched by Start.
func (s *Supervisor) Register(name string, fn Func) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workers = append(s.workers, named{name: name, fn: fn})
}

// Start launches every registered worker with ctx and returns a wait func that
// blocks until all of them have returned (call it after cancelling ctx).
func (s *Supervisor) Start(ctx context.Context) (wait func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var wg sync.WaitGroup
	for _, w := range s.workers {
		wg.Add(1)
		go func(w named) {
			defer wg.Done()
			w.fn(ctx)
			slog.Info("worker stopped", "name", w.name)
		}(w)
	}
	return wg.Wait
}
