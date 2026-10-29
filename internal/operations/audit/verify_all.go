package audit

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
)

// ErrChainBroken is VerifyAll's error when a chain doesn't verify.
var ErrChainBroken = errors.New("audit chain broken")

var verifyFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "audit_verify_failures_total",
	Help: "Scheduled audit-chain verifications that found a broken chain or could not run.",
})

// BrokenChain is one chain that failed verification: its organisation, or nil
// and its shard for a platform chain, the first row that doesn't verify (nil
// for a platform chain with no row), and why.
type BrokenChain struct {
	TenantID *uuid.UUID
	Shard    int16
	EventID  *uuid.UUID
	Reason   string
}

// VerificationRun is one verification of every chain, as VerifyAll stores it
// in platform.audit_verification_runs. Scope is "all" when it walked every
// chain from its first row, "incremental" when from their checkpoints. Outcome
// is "intact", "broken" (a chain does not verify) or "error" (a chain could not
// be read, which stops the run).
type VerificationRun struct {
	ID            uuid.UUID
	StartedAt     time.Time
	FinishedAt    time.Time
	Scope         string
	TenantsWalked int
	RowsChecked   int
	Outcome       string
	Broken        []BrokenChain
	Err           string
}

// FullVerifyInterval is how often VerifyAll walks every chain from its first
// row rather than from its checkpoint, so a changed old row is still found.
const FullVerifyInterval = 7 * 24 * time.Hour

// VerifyAll verifies the platform chains and every organisation's chain, and
// stores the run. Once its checkpoint row, the last a run found intact, is
// checked unchanged, a chain is walked on from it; from its first row when it
// has none, was found broken, or no run has walked every chain from the start
// within FullVerifyInterval. A broken chain is logged at ERROR; the stored run
// names the first. A broken or failed run counts toward
// audit_verify_failures_total and returns an error, so the job records a
// failure.
func (v *Verifier) VerifyAll(ctx context.Context) (VerificationRun, error) {
	full, err := v.q.CountFullAuditVerificationsSince(ctx, time.Now().Add(-FullVerifyInterval))
	if err != nil {
		slog.Warn("audit chain verification: find the last full run", "err", err)
	}
	return v.verifyAll(ctx, err != nil || full == 0)
}

// verifyAll is VerifyAll, walking every chain from its first row if fromStart.
func (v *Verifier) verifyAll(ctx context.Context, fromStart bool) (VerificationRun, error) {
	run := VerificationRun{ID: uuid.New(), StartedAt: time.Now(), Scope: "incremental", Outcome: "intact"}
	if fromStart {
		run.Scope = "all"
	}
	runErr, unsaved := v.walkAll(ctx, &run, fromStart)
	if runErr != nil {
		run.Outcome, run.Err = "error", runErr.Error()
	}
	run.FinishedAt = time.Now()

	walked := run.TenantsWalked
	if walked > math.MaxInt32 {
		walked = math.MaxInt32
	}
	arg := dbgen.InsertAuditVerificationRunParams{
		ID: run.ID, StartedAt: run.StartedAt, FinishedAt: run.FinishedAt, Scope: run.Scope,
		TenantsWalked: int32(walked), RowsChecked: int64(run.RowsChecked), Outcome: run.Outcome,
	}
	if len(run.Broken) > 0 {
		first := run.Broken[0]
		arg.BrokenTenantID, arg.FirstBrokenLink, arg.BrokenReason = pgUUIDNullable(first.TenantID), pgUUIDNullable(first.EventID), &first.Reason
	}
	if run.Err != "" {
		arg.Error = &run.Err
	}
	if err := v.q.InsertAuditVerificationRun(context.WithoutCancel(ctx), arg); err != nil && runErr == nil {
		runErr = err
	}

	if run.Outcome != "intact" {
		verifyFailures.Inc()
	}
	if runErr == nil && run.Outcome == "broken" {
		runErr = ErrChainBroken
	}
	if runErr == nil {
		runErr = unsaved
	}
	return run, runErr
}

// walkAll walks every chain into run and keeps each one's checkpoint. It
// returns the error that stopped it, if any, and the last checkpoint it failed
// to store.
func (v *Verifier) walkAll(ctx context.Context, run *VerificationRun, fromStart bool) (stopped, unsaved error) {
	tenants, err := v.q.ListAuditChainTenants(ctx)
	if err != nil {
		return err, nil
	}
	saved, err := v.checkpoints(ctx)
	if err != nil {
		return err, nil
	}
	chains := make([]chain, 0, PlatformChainShards+len(tenants))
	for shard := range int16(PlatformChainShards) {
		chains = append(chains, chain{shard: shard})
	}
	for _, t := range tenants {
		chains = append(chains, chain{tenant: &t})
	}
	for _, c := range chains {
		began, ok := saved[c.key()]
		from := &began
		if !ok {
			from = nil
		}
		// A chain found broken is walked from the start until its checkpoint
		// is deleted, so every run reports it again.
		res, last, err := v.walk(ctx, c.tenant, c.shard, from, fromStart || began.Broken)
		if err != nil {
			return err, unsaved
		}
		if c.tenant != nil {
			run.TenantsWalked++
		}
		run.RowsChecked += res.RowsChecked
		if !res.OK {
			run.Outcome = "broken"
			run.Broken = append(run.Broken, BrokenChain{TenantID: c.tenant, Shard: c.shard, EventID: res.BrokenAtID, Reason: res.BrokenReason})
			slog.Error("audit chain verification failed: chain broken",
				"tenant_id", c.label(), "event_id", res.BrokenAtID, "reason", res.BrokenReason)
		}
		if err := v.keepCheckpoint(ctx, c, from, last, res.OK); err != nil {
			slog.Error("audit chain verification: store the checkpoint", "tenant_id", c.label(), "err", err)
			unsaved = err
		}
	}
	stray, err := v.strayPlatformRow(ctx)
	if err != nil {
		return err, unsaved
	}
	if stray != nil {
		run.Outcome = "broken"
		run.Broken = append(run.Broken, *stray)
		slog.Error("audit chain verification failed: a platform row is on no chain",
			"event_id", stray.EventID, "reason", stray.Reason)
	}
	return nil, unsaved
}

// checkpoints returns every chain's checkpoint by its chain's key.
func (v *Verifier) checkpoints(ctx context.Context) (map[chainKey]checkpoint, error) {
	rows, err := v.q.ListAuditChainCheckpoints(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[chainKey]checkpoint, len(rows))
	for _, r := range rows {
		out[chain{tenant: toUUIDPtr(r.TenantID), shard: r.ChainShard}.key()] = checkpoint{
			EventID: r.EventID, CreatedAt: r.EventCreatedAt, RowHash: trimmed(&r.RowHash), Broken: r.Broken,
		}
	}
	return out, nil
}

// keepCheckpoint moves c's checkpoint on from began, where this run found it,
// to last, the last row it found intact, unless another run has moved it
// since. A broken chain's checkpoint is marked broken instead and stays where
// it is.
func (v *Verifier) keepCheckpoint(ctx context.Context, c chain, began, last *checkpoint, intact bool) error {
	tid := pgUUIDNullable(c.tenant)
	switch {
	case began != nil && began.Broken:
		return nil
	case !intact && began != nil:
		return v.q.MarkAuditChainCheckpointBroken(ctx, dbgen.MarkAuditChainCheckpointBrokenParams{
			EventID: began.EventID, ChainShard: c.shard, TenantID: tid,
		})
	case !intact, last == nil, began != nil && last.EventID == began.EventID:
		return nil
	case began == nil:
		return v.q.InsertAuditChainCheckpoint(ctx, dbgen.InsertAuditChainCheckpointParams{
			TenantID: tid, ChainShard: c.shard, EventID: last.EventID, EventCreatedAt: last.CreatedAt, RowHash: last.RowHash,
		})
	default:
		return v.q.AdvanceAuditChainCheckpoint(ctx, dbgen.AdvanceAuditChainCheckpointParams{
			EventID: last.EventID, EventCreatedAt: last.CreatedAt, RowHash: last.RowHash,
			FromEventID: began.EventID, ChainShard: c.shard, TenantID: tid,
		})
	}
}

// chain names one hash chain: an organisation's, or with a nil tenant platform
// chain shard.
type chain struct {
	tenant *uuid.UUID
	shard  int16
}

// chainKey is a chain as a map key: its organisation, uuid.Nil for a platform
// chain, and its shard.
type chainKey struct {
	tenant uuid.UUID
	shard  int16
}

func (c chain) key() chainKey {
	if c.tenant == nil {
		return chainKey{shard: c.shard}
	}
	return chainKey{tenant: *c.tenant, shard: c.shard}
}

// label names c in logs: its organisation, or "platform/<shard>".
func (c chain) label() string {
	if c.tenant == nil {
		return "platform/" + strconv.Itoa(int(c.shard))
	}
	return c.tenant.String()
}

// VerificationMetrics returns the audit_verify_last_success_timestamp_seconds
// gauge: when a scheduled verification on any instance last found every chain
// intact (0 if never), for alerting.
func VerificationMetrics(pool *pgxpool.Pool) prometheus.Collector {
	q := dbgen.New(pool)
	return prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "audit_verify_last_success_timestamp_seconds",
		Help: "When a scheduled audit-chain verification last found every chain intact (Unix seconds; 0: never).",
	}, func() float64 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		at, err := q.LastIntactAuditVerification(ctx)
		if err != nil {
			return 0
		}
		return at
	})
}
