//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	worker "github.com/qeetgroup/qeet-id-server/internal/platform/jobs"
)

// TestScheduledJobsRunOncePerInterval pins the scheduler (QTID-326): a due
// job runs once however many instances look for it at the same moment, not
// again within its interval, and again once the interval has passed; a job
// that fails or panics is recorded and the next one still runs.
func TestScheduledJobsRunOncePerInterval(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	name := "test-job-" + uuid.NewString()
	var runs atomic.Int32
	job := worker.Scheduled{Name: name, Interval: time.Hour, Run: func(context.Context) error {
		runs.Add(1)
		return nil
	}}
	jobs := []worker.Scheduled{job}

	t.Run("five instances looking at once run it once", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 5 {
			wg.Go(func() { worker.RunDue(ctx, testPool, jobs) })
		}
		wg.Wait()
		if n := runs.Load(); n != 1 {
			t.Fatalf("ran %d times, want 1", n)
		}
	})

	t.Run("not again within its interval", func(t *testing.T) {
		if ran := worker.RunDue(ctx, testPool, jobs); len(ran) != 0 || runs.Load() != 1 {
			t.Fatalf("ran %v (%d runs) within the interval, want none", ran, runs.Load())
		}
	})

	t.Run("again once the interval has passed, and the success is recorded", func(t *testing.T) {
		if _, err := testPool.Exec(ctx, `UPDATE platform.scheduled_job_runs SET last_started_at = now() - interval '2 hours'
			WHERE job = $1`, name); err != nil {
			t.Fatal(err)
		}
		worker.RunDue(ctx, testPool, jobs)
		if n := runs.Load(); n != 2 {
			t.Fatalf("ran %d times after the interval, want 2", n)
		}
		var succeeded bool
		var lastErr *string
		if err := testPool.QueryRow(ctx, `SELECT last_succeeded_at IS NOT NULL, last_error FROM platform.scheduled_job_runs
			WHERE job = $1`, name).Scan(&succeeded, &lastErr); err != nil || !succeeded || lastErr != nil {
			t.Fatalf("recorded success %v, error %v (%v)", succeeded, lastErr, err)
		}
	})

	t.Run("a failing or panicking job is recorded, and the next still runs", func(t *testing.T) {
		prefix := "test-job-" + uuid.NewString()
		var okRan atomic.Bool
		ran := worker.RunDue(ctx, testPool, []worker.Scheduled{
			{Name: prefix + "-fails", Interval: time.Hour, Run: func(context.Context) error { return errors.New("boom") }},
			{Name: prefix + "-panics", Interval: time.Hour, Run: func(context.Context) error { panic("kaput") }},
			{Name: prefix + "-ok", Interval: time.Hour, Run: func(context.Context) error { okRan.Store(true); return nil }},
		})
		if len(ran) != 3 || !okRan.Load() {
			t.Fatalf("ran %v, ok job ran %v; want all three", ran, okRan.Load())
		}
		for suffix, want := range map[string]string{"-fails": "boom", "-panics": "kaput"} {
			var lastErr *string
			var succeeded bool
			if err := testPool.QueryRow(ctx, `SELECT last_error, last_succeeded_at IS NOT NULL FROM platform.scheduled_job_runs
				WHERE job = $1`, prefix+suffix).Scan(&lastErr, &succeeded); err != nil {
				t.Fatal(err)
			}
			if lastErr == nil || !strings.Contains(*lastErr, want) || succeeded {
				t.Fatalf("%s: recorded error %v, succeeded %v; want %q and no success", suffix, lastErr, succeeded, want)
			}
		}
	})

	t.Run("the API's maintenance jobs are all scheduled", func(t *testing.T) {
		var names []string
		for _, j := range bootstrap.MaintenanceJobs(testPool, nil) {
			names = append(names, j.Name)
			if j.Interval <= 0 || j.Run == nil {
				t.Fatalf("job %s has no interval or body", j.Name)
			}
		}
		if len(names) != 5 || names[0] != "audit-chain-verify" {
			t.Fatalf("maintenance jobs = %v", names)
		}
	})
}

// TestEveryAuditChainIsVerifiedAndStored pins the scheduled verification
// (QTID-326): it walks every organisation's chain, not only the platform's,
// stores each run, and a tampered row fails the run, naming the organisation
// and the row.
func TestEveryAuditChainIsVerifiedAndStored(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("chain"))
	for range 3 {
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID: &tenantID, ActorType: "system", Action: "test.chain_event", ResourceType: "test",
		}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var middle uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM audit.events WHERE tenant_id = $1 AND action = 'test.chain_event'
		ORDER BY created_at, id OFFSET 1 LIMIT 1`, tenantID).Scan(&middle); err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewVerifier(testPool)
	brokenFor := func(run audit.VerificationRun) *audit.BrokenChain {
		for i, b := range run.Broken {
			if b.TenantID != nil && *b.TenantID == tenantID {
				return &run.Broken[i]
			}
		}
		return nil
	}
	stored := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		var outcome string
		if err := testPool.QueryRow(ctx, `SELECT outcome FROM platform.audit_verification_runs WHERE id = $1`, id).Scan(&outcome); err != nil {
			t.Fatalf("the run wasn't stored: %v", err)
		}
		return outcome
	}

	t.Run("an organisation's intact chain is walked, and the run stored", func(t *testing.T) {
		run, err := verifier.VerifyAll(ctx)
		if run.Outcome == "error" {
			t.Fatalf("verification failed to run: %v", err)
		}
		if b := brokenFor(run); b != nil {
			t.Fatalf("an intact chain reported broken: %+v", b)
		}
		if run.TenantsWalked < 1 || run.RowsChecked < 3 {
			t.Fatalf("walked %d organisation(s), %d row(s); want this one's chain walked", run.TenantsWalked, run.RowsChecked)
		}
		if got := stored(t, run.ID); got != run.Outcome {
			t.Fatalf("stored outcome %q, want %q", got, run.Outcome)
		}
	})

	t.Run("a tampered row fails the run, naming the organisation and the row", func(t *testing.T) {
		if _, err := testPool.Exec(ctx, `UPDATE audit.events SET action = 'test.tampered' WHERE id = $1`, middle); err != nil {
			t.Fatal(err)
		}
		run, err := verifier.VerifyAll(ctx)
		if !errors.Is(err, audit.ErrChainBroken) || run.Outcome != "broken" {
			t.Fatalf("after tampering: outcome %q, err %v; want broken", run.Outcome, err)
		}
		b := brokenFor(run)
		if b == nil || b.EventID == nil || *b.EventID != middle {
			t.Fatalf("broken chains %+v; want this organisation's, at row %s", run.Broken, middle)
		}
		if got := stored(t, run.ID); got != "broken" {
			t.Fatalf("stored outcome %q, want broken", got)
		}
	})
}
