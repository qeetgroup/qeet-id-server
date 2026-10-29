package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Scheduled is a maintenance job that runs once per Interval across every
// instance running the scheduler. Before running it an instance
// claims it in platform.scheduled_job_runs, and only a claim older than the
// interval can be taken, so two instances never both run it in one interval.
type Scheduled struct {
	Name     string
	Interval time.Duration
	Run      func(ctx context.Context) error
}

// SchedulerTick is how often an instance looks for due jobs.
const SchedulerTick = time.Minute

var (
	scheduledFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "scheduled_job_failures_total",
		Help: "Scheduled maintenance job runs that failed, by job.",
	}, []string{"job"})
	scheduledDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "scheduled_job_duration_seconds",
		Help:    "How long each scheduled maintenance job run took, by job.",
		Buckets: prometheus.ExponentialBuckets(0.01, 4, 10),
	}, []string{"job"})
)

// RunScheduled runs the jobs until ctx ends, then waits for those still
// running. Each runs when it is due: at start if it has never run or its last
// run began longer ago than its interval, then once per interval, in its own
// goroutine so a slow one doesn't hold up the others.
func RunScheduled(ctx context.Context, pool *pgxpool.Pool, jobs []Scheduled, tick time.Duration) {
	s := newScheduler(pool, jobs)
	defer s.wg.Wait()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		s.startDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue starts every job that is due and that this instance claims, at most
// maxRunningJobs of them, each in its own goroutine, and returns the names of
// those it ran once they have all finished. A failing or panicking job is
// recorded and the others still run.
func RunDue(ctx context.Context, pool *pgxpool.Pool, jobs []Scheduled) []string {
	s := newScheduler(pool, jobs)
	ran := s.startDue(ctx)
	s.wg.Wait()
	return ran
}

// maxRunningJobs is how many jobs an instance runs at once, so the scheduler
// leaves most of a shared connection pool to requests.
const maxRunningJobs = 4

// scheduler runs claimed jobs in goroutines and knows which are still running
// on this instance, so a later tick doesn't start one again.
type scheduler struct {
	pool    *pgxpool.Pool
	jobs    []Scheduled
	wg      sync.WaitGroup
	mu      sync.Mutex
	running map[string]bool
}

func newScheduler(pool *pgxpool.Pool, jobs []Scheduled) *scheduler {
	return &scheduler{pool: pool, jobs: jobs, running: map[string]bool{}}
}

// startDue claims and starts each due job not already running here, while
// fewer than maxRunningJobs run, and returns the names of those it started.
// The rest wait for a later call.
func (s *scheduler) startDue(ctx context.Context) []string {
	var started []string
	for _, j := range s.jobs {
		if ctx.Err() != nil {
			return started
		}
		s.mu.Lock()
		busy, full := s.running[j.Name], len(s.running) >= maxRunningJobs
		s.mu.Unlock()
		if full {
			return started
		}
		if busy {
			continue
		}
		claimed, err := claimJob(ctx, s.pool, j)
		if err != nil {
			slog.Error("scheduled job: claim", "job", j.Name, "err", err)
			continue
		}
		if !claimed {
			continue
		}
		s.mu.Lock()
		s.running[j.Name] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.run(ctx, j)
			s.mu.Lock()
			delete(s.running, j.Name)
			s.mu.Unlock()
		}()
		started = append(started, j.Name)
	}
	return started
}

// run runs a claimed job and records how it ended.
func (s *scheduler) run(ctx context.Context, j Scheduled) {
	start := time.Now()
	err := runJob(ctx, j)
	elapsed := time.Since(start)
	scheduledDuration.WithLabelValues(j.Name).Observe(elapsed.Seconds())
	if err != nil {
		scheduledFailures.WithLabelValues(j.Name).Inc()
		slog.Error("scheduled job failed", "job", j.Name, "err", err, "duration_ms", elapsed.Milliseconds())
	} else {
		slog.Info("scheduled job complete", "job", j.Name, "duration_ms", elapsed.Milliseconds())
	}
	if ferr := finishJob(context.WithoutCancel(ctx), s.pool, j.Name, err); ferr != nil {
		slog.Error("scheduled job: record outcome", "job", j.Name, "err", ferr)
	}
}

// runJob runs one job, turning a panic into its error.
func runJob(ctx context.Context, j Scheduled) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	return j.Run(ctx)
}

// claimJob takes the job for this interval, or reports false when it was
// already taken in it. The row lock ON CONFLICT takes makes the claim atomic
// across instances: the second one sees the first one's start and gets no row.
func claimJob(ctx context.Context, pool *pgxpool.Pool, j Scheduled) (bool, error) {
	var name string
	err := pool.QueryRow(ctx, `
		INSERT INTO platform.scheduled_job_runs (job, last_started_at) VALUES ($1, now())
		ON CONFLICT (job) DO UPDATE SET last_started_at = now()
		WHERE platform.scheduled_job_runs.last_started_at <= now() - make_interval(secs => $2)
		RETURNING job`, j.Name, j.Interval.Seconds()).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// finishJob records how a run ended.
func finishJob(ctx context.Context, pool *pgxpool.Pool, name string, runErr error) error {
	var msg *string
	if runErr != nil {
		s := runErr.Error()
		if len(s) > 2000 {
			s = s[:2000]
		}
		msg = &s
	}
	_, err := pool.Exec(ctx, `
		UPDATE platform.scheduled_job_runs
		SET last_finished_at = now(), last_error = $2::text,
		    last_succeeded_at = CASE WHEN $2::text IS NULL THEN now() ELSE last_succeeded_at END
		WHERE job = $1`, name, msg)
	return err
}

// LastSuccessCollector reports scheduled_job_last_success_timestamp_seconds
// for each job from platform.scheduled_job_runs, whichever instance ran it,
// so an alert can fire when a job hasn't succeeded within its interval.
func LastSuccessCollector(pool *pgxpool.Pool) prometheus.Collector {
	return &lastSuccess{pool: pool, desc: prometheus.NewDesc(
		"scheduled_job_last_success_timestamp_seconds",
		"When each scheduled maintenance job last succeeded, on any instance (Unix seconds).",
		[]string{"job"}, nil)}
}

type lastSuccess struct {
	pool *pgxpool.Pool
	desc *prometheus.Desc
}

func (c *lastSuccess) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *lastSuccess) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := c.pool.Query(ctx, `SELECT job, extract(epoch FROM last_succeeded_at)::float8
		FROM platform.scheduled_job_runs WHERE last_succeeded_at IS NOT NULL`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var job string
		var at float64
		if rows.Scan(&job, &at) == nil {
			ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, at, job)
		}
	}
}
