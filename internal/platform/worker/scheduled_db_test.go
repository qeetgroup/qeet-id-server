//go:build integration

package worker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// jobName is a job name no other test uses, since every job's claim is a row
// of the one table.
func jobName(name string) string { return name + "-" + uuid.NewString() }

// TestSlowJobDoesNotHoldUpTheOthers checks that while one job runs the others
// keep running on time, the next ticks don't start it again, and the
// scheduler waits for it when it stops.
func TestSlowJobDoesNotHoldUpTheOthers(t *testing.T) {
	release := make(chan struct{})
	var released sync.Once
	t.Cleanup(func() { released.Do(func() { close(release) }) })
	var slowStarts, quickRuns atomic.Int32
	jobs := []Scheduled{
		{Name: jobName("slow"), Interval: time.Millisecond, Run: func(context.Context) error {
			slowStarts.Add(1)
			<-release
			return nil
		}},
		{Name: jobName("quick"), Interval: time.Millisecond, Run: func(context.Context) error {
			quickRuns.Add(1)
			return nil
		}},
	}
	ctx, cancel := context.WithCancel(dbtest.Context(t))
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		RunScheduled(ctx, dbtest.Pool(t), jobs, 10*time.Millisecond)
		close(stopped)
	}()

	for deadline := time.Now().Add(10 * time.Second); quickRuns.Load() < 3 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := quickRuns.Load(); n < 3 {
		t.Errorf("the quick job ran %d times while the slow one ran, want at least 3", n)
	}
	if n := slowStarts.Load(); n != 1 {
		t.Errorf("the slow job started %d times while it was still running, want once", n)
	}
	cancel()
	select {
	case <-stopped:
		t.Error("the scheduler stopped before its running job finished")
	case <-time.After(50 * time.Millisecond):
	}
	released.Do(func() { close(release) })
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the scheduler didn't stop once its job finished")
	}
}

// TestRunDueRunsJobsTogether checks that runDue runs the due jobs at the same
// time, records a panicking one as failed, returns once they have finished,
// and doesn't run them again in the same interval.
func TestRunDueRunsJobsTogether(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	var bothStarted sync.WaitGroup
	bothStarted.Add(2)
	together := func(context.Context) error {
		bothStarted.Done()
		met := make(chan struct{})
		go func() { bothStarted.Wait(); close(met) }()
		select {
		case <-met:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("the other job never started")
		}
	}
	a, b, panics := jobName("a"), jobName("b"), jobName("panics")
	jobs := []Scheduled{
		{Name: a, Interval: time.Hour, Run: together},
		{Name: b, Interval: time.Hour, Run: together},
		{Name: panics, Interval: time.Hour, Run: func(context.Context) error { panic("boom") }},
	}
	ran := runDue(ctx, pool, jobs)
	slices.Sort(ran)
	want := []string{a, b, panics}
	slices.Sort(want)
	if !slices.Equal(ran, want) {
		t.Errorf("runDue ran %v, want %v", ran, want)
	}
	for _, job := range []string{a, b, panics} {
		var lastError *string
		var finished bool
		if err := pool.QueryRow(ctx, `
			SELECT last_error, last_finished_at IS NOT NULL FROM platform.scheduled_job_runs WHERE job = $1`,
			job).Scan(&lastError, &finished); err != nil {
			t.Fatal(err)
		}
		failed := job == panics
		if !finished || (lastError != nil) != failed || (failed && !strings.HasPrefix(*lastError, "panic: boom")) {
			t.Errorf("job %s: finished %v, last error %v; want it finished, failed only if it panicked", job, finished, lastError)
		}
	}
	if again := runDue(ctx, pool, jobs); len(again) != 0 {
		t.Errorf("runDue ran %v again within their interval, want none", again)
	}
}

// TestRunDueStartsAtMostMaxRunningJobs checks that an instance runs no more
// than maxRunningJobs at once, and the rest run at the next call.
func TestRunDueStartsAtMostMaxRunningJobs(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	release := make(chan struct{})
	var jobs []Scheduled
	for range maxRunningJobs + 1 {
		jobs = append(jobs, Scheduled{Name: jobName("job"), Interval: time.Hour, Run: func(context.Context) error {
			<-release
			return nil
		}})
	}
	s := newScheduler(pool, jobs)
	started := s.startDue(ctx)
	close(release)
	s.wg.Wait()
	if len(started) != maxRunningJobs {
		t.Errorf("%d jobs started at once, want %d", len(started), maxRunningJobs)
	}
	if ran := runDue(ctx, pool, jobs); !slices.Equal(ran, []string{jobs[maxRunningJobs].Name}) {
		t.Errorf("the next runDue ran %v, want the one left, %s", ran, jobs[maxRunningJobs].Name)
	}
}

// runDue starts every job that is due and that this instance claims, as one
// scheduler tick does, and returns the names of those it ran once they have
// all finished.
func runDue(ctx context.Context, pool *pgxpool.Pool, jobs []Scheduled) []string {
	s := newScheduler(pool, jobs)
	ran := s.startDue(ctx)
	s.wg.Wait()
	return ran
}
