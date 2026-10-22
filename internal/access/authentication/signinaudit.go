package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
)

// Failed sign-ins are recorded in the organisation's audit trail as
// auth.sign_in_failed, never with what was submitted; locks and throttles are
// recorded too. Records are capped per organisation and network, and failures
// past the cap are counted in sign_in_failures_unrecorded_total.

// How a sign-in failed, as recorded.
const (
	FailureWrongPassword   = "wrong_password"
	FailureUnknownAccount  = "unknown_account"
	FailureAccountLocked   = "account_locked"
	FailureSourceThrottled = "source_throttled"
	FailureCodeInvalid     = "code_invalid"
)

// SignInFailure is a failed sign-in, as recorded.
type SignInFailure struct {
	TenantID  uuid.UUID      // the organisation signed in to (uuid.Nil: the account's own)
	UserID    uuid.UUID      // the account, if one was found (uuid.Nil: none)
	Method    string         // password, mfa or passkey
	Reason    string         // a Failure* value, such as FailureWrongPassword
	IP        string         // the client address
	UserAgent string         // the client's User-Agent
	Metadata  map[string]any // extra details, never anything submitted
}

var unrecordedFailures = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "sign_in_failures_unrecorded_total",
	Help: "Failed sign-ins not written to the audit trail because the bound on such records was reached, by method (password, mfa, passkey).",
}, []string{"method"})

func init() {
	// Publish every series at zero so an alert can rate() it from the start.
	for _, method := range []string{"password", "mfa", "passkey"} {
		unrecordedFailures.WithLabelValues(method)
	}
}

// failureBound bounds how many failed sign-ins are recorded.
type failureBound struct {
	perSource, perTenant *ratelimit.Limiter
}

func newFailureBound() failureBound {
	return failureBound{
		perSource: ratelimit.New(1.0/6, 20), // per organisation and source network: 20, then ten a minute
		perTenant: ratelimit.New(2, 200),    // per organisation: 200, then two a second
	}
}

func (b failureBound) allow(ctx context.Context, f SignInFailure) bool {
	org := f.TenantID.String()
	if ok, _ := b.perSource.Take(ctx, org+"|"+SourceNetwork(f.IP)); !ok {
		return false
	}
	ok, _ := b.perTenant.Take(ctx, org)
	return ok
}

// RecordSignInFailure records a failed sign-in in the audit trail, within the
// bound. Best effort: a record that can't be written is logged, and the
// sign-in's answer is unchanged.
func (s *Service) RecordSignInFailure(ctx context.Context, f SignInFailure) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if f.TenantID == uuid.Nil && f.UserID != uuid.Nil {
		f.TenantID = s.homeTenant(ctx, f.UserID)
	}
	if !s.failures.allow(ctx, f) {
		unrecordedFailures.WithLabelValues(f.Method).Inc()
		return
	}
	meta := map[string]any{"method": f.Method, "reason": f.Reason}
	if network := SourceNetwork(f.IP); network != "" {
		meta["network"] = network
	}
	for k, v := range f.Metadata {
		meta[k] = v
	}
	e := audit.Event{TenantID: orNil(f.TenantID), ActorType: "anonymous", Action: "auth.sign_in_failed",
		IP: f.IP, UserAgent: f.UserAgent, Metadata: meta}
	if f.UserID != uuid.Nil {
		user := f.UserID
		e.ActorUserID, e.ActorType, e.ResourceType, e.ResourceID = &user, "user", "user", &user
	}
	if err := s.auditTx(ctx, e); err != nil {
		slog.Warn("auth: record a failed sign-in", "method", f.Method, "reason", f.Reason, "err", err)
	}
}

// recordLocks records the locks and the throttle a failed sign-in set. Each is
// set once per period, so these need no bound.
func (s *Service) recordLocks(ctx context.Context, f SignInFailure, locks []AccountLock, throttle *SourceThrottle) {
	if len(locks) == 0 && throttle == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if f.TenantID == uuid.Nil && f.UserID != uuid.Nil {
		f.TenantID = s.homeTenant(ctx, f.UserID)
	}
	var user *uuid.UUID
	if f.UserID != uuid.Nil {
		id := f.UserID
		user = &id
	}
	for _, lock := range locks {
		e := audit.Event{TenantID: orNil(f.TenantID), ActorType: "system", Action: "auth.account_locked",
			IP: f.IP, UserAgent: f.UserAgent, Metadata: map[string]any{
				"counter": lock.Counter, "network": lock.Network, "failures": lock.Failures, "threshold": lock.Threshold,
				"window_seconds": int(lock.Window.Seconds()), "locked_until": lock.LockedUntil.UTC().Format(time.RFC3339),
			}}
		if user != nil {
			e.ResourceType, e.ResourceID = "user", user
		}
		if err := s.auditTx(ctx, e); err != nil {
			slog.Warn("auth: record a sign-in lock", "counter", lock.Counter, "err", err)
		}
	}
	if throttle != nil {
		if err := s.auditTx(ctx, audit.Event{TenantID: orNil(f.TenantID), ActorType: "system", Action: "auth.source_throttled",
			IP: f.IP, UserAgent: f.UserAgent, Metadata: map[string]any{
				"network": throttle.Network, "distinct_accounts": len(throttle.Accounts),
				"window_seconds": int(throttle.Window.Seconds()), "throttled_until": throttle.ThrottledUntil.UTC().Format(time.RFC3339),
			}}); err != nil {
			slog.Warn("auth: record a source throttle", "err", err)
		}
	}
}

// homeTenant is the organisation an account belongs to (uuid.Nil: none, or
// it can't be read).
func (s *Service) homeTenant(ctx context.Context, userID uuid.UUID) uuid.UUID {
	var tenantID *uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM "user".users WHERE id = $1`, userID).Scan(&tenantID); err != nil || tenantID == nil {
		return uuid.Nil
	}
	return *tenantID
}

func orNil(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
