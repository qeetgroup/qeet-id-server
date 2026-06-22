package worker_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id/platform/worker"
)

func TestSupervisorStartsAndStops(t *testing.T) {
	sup := worker.New()
	var started, stopped atomic.Int32

	mk := func() worker.Func {
		return func(ctx context.Context) {
			started.Add(1)
			<-ctx.Done()
			stopped.Add(1)
		}
	}
	sup.Register("a", mk())
	sup.Register("b", mk())

	ctx, cancel := context.WithCancel(context.Background())
	wait := sup.Start(ctx)

	// Give the goroutines a moment to enter their run funcs.
	deadline := time.Now().Add(time.Second)
	for started.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if started.Load() != 2 {
		t.Fatalf("started = %d, want 2", started.Load())
	}

	cancel()
	wait() // must return once both workers observe cancellation
	if stopped.Load() != 2 {
		t.Fatalf("stopped = %d, want 2", stopped.Load())
	}
}

func TestSupervisorNoWorkers(t *testing.T) {
	sup := worker.New()
	wait := sup.Start(context.Background())
	wait() // must not block when nothing is registered
}
