package audit

import (
	"context"
	"errors"
	"log/slog"
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

// BrokenChain is one chain that failed verification: its organisation (nil
// for the platform chain), the first row that doesn't verify, and why.
type BrokenChain struct {
	TenantID *uuid.UUID
	EventID  *uuid.UUID
	Reason   string
}

// VerificationRun is one verification of every chain, as VerifyAll stores it
// in platform.audit_verification_runs.
type VerificationRun struct {
	ID            uuid.UUID
	StartedAt     time.Time
	FinishedAt    time.Time
	TenantsWalked int
	RowsChecked   int
	// Outcome is intact, broken (a chain doesn't verify) or error (a chain
	// couldn't be read; the run stops there).
	Outcome string
	Broken  []BrokenChain
	Err     string
}

// VerifyAll verifies the platform chain and every organisation's chain
// (QTID-326; Verify(ctx, nil) alone is the platform chain only) and stores the
// run. Each broken chain is logged at ERROR with its organisation and row; the
// stored run names the first. A broken or failed run counts toward
// audit_verify_failures_total and returns an error, so the scheduled job
// records a failure.
func (v *Verifier) VerifyAll(ctx context.Context) (VerificationRun, error) {
	run := VerificationRun{ID: uuid.New(), StartedAt: time.Now(), Outcome: "intact"}
	var runErr error
	tenants, err := v.q.ListAuditChainTenants(ctx)
	if err != nil {
		run.Outcome, run.Err, runErr = "error", err.Error(), err
	}
	scopes := []*uuid.UUID{nil}
	for _, t := range tenants {
		scopes = append(scopes, toUUIDPtr(t))
	}
	for _, tenantID := range scopes {
		if runErr != nil {
			break
		}
		res, err := v.Verify(ctx, tenantID)
		if err != nil {
			run.Outcome, run.Err, runErr = "error", err.Error(), err
			break
		}
		if tenantID != nil {
			run.TenantsWalked++
		}
		run.RowsChecked += res.RowsChecked
		if !res.OK {
			run.Outcome = "broken"
			run.Broken = append(run.Broken, BrokenChain{TenantID: tenantID, EventID: res.BrokenAtID, Reason: res.BrokenReason})
			slog.Error("audit chain verification failed: chain broken",
				"tenant_id", scopeLabel(tenantID), "event_id", res.BrokenAtID, "reason", res.BrokenReason)
		}
	}
	run.FinishedAt = time.Now()

	arg := dbgen.InsertAuditVerificationRunParams{
		ID: run.ID, StartedAt: run.StartedAt, FinishedAt: run.FinishedAt,
		TenantsWalked: int32(run.TenantsWalked), RowsChecked: int64(run.RowsChecked), Outcome: run.Outcome,
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
	return run, runErr
}

func scopeLabel(tenantID *uuid.UUID) string {
	if tenantID == nil {
		return "platform"
	}
	return tenantID.String()
}

// VerificationMetrics reports audit_verify_last_success_timestamp_seconds:
// when a scheduled verification last found every chain intact, on any
// instance (0: never), so an alert can fire when none has for an interval.
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
