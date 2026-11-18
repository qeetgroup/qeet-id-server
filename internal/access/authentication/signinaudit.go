package authentication

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Failed sign-ins are recorded in the organization's audit trail as
// auth.sign_in_failed, never with what was submitted; locks and throttles are
// recorded too. Records are capped per organization and network, and failures
// past the cap are counted in sign_in_failures_unrecorded_total.

// How a sign-in failed, as recorded.
const (
	FailureWrongPassword   = "wrong_password"
	FailureUnknownAccount  = "unknown_account"
	FailureAccountLocked   = "account_locked"
	FailureSourceThrottled = "source_throttled"
	FailureCodeInvalid     = "code_invalid"
)

// SignInFailure is a failed sign-in, as recorded. Its Actor is the attempt's
// client address, user agent and request ID; the record names the account,
// if one was found, as the actor.
type SignInFailure struct {
	OrganizationID uuid.UUID      // the organization signed in to (uuid.Nil: the account's own)
	UserID         uuid.UUID      // the account, if one was found (uuid.Nil: none)
	Method         string         // password, mfa or passkey
	Reason         string         // a Failure* value, such as FailureWrongPassword
	Metadata       map[string]any // extra details, never anything submitted
	audit.Actor
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
	perSource, perOrganization *ratelimit.Limiter
}

func newFailureBound() failureBound {
	return failureBound{
		perSource:       ratelimit.New(1.0/6, 20), // per organization and source network: 20, then ten a minute
		perOrganization: ratelimit.New(2, 200),    // per organization: 200, then two a second
	}
}

func (b failureBound) allow(ctx context.Context, f SignInFailure) bool {
	org := f.OrganizationID.String()
	if ok, _ := b.perSource.Take(ctx, org+"|"+httpx.SourceNetwork(f.IP)); !ok {
		return false
	}
	ok, _ := b.perOrganization.Take(ctx, org)
	return ok
}

// RecordSignInFailure records a failed sign-in in the audit trail, within the
// bound. Best effort: a record that can't be written is logged, and the
// sign-in's answer is unchanged.
func (s *Service) RecordSignInFailure(ctx context.Context, f SignInFailure) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if f.OrganizationID == uuid.Nil && f.UserID != uuid.Nil {
		f.OrganizationID = s.homeOrganization(ctx, f.UserID)
	}
	method := f.Method
	if method == "" {
		method = "unknown"
	}
	reason := f.Reason
	if reason == "" {
		reason = "refused"
	}
	signIns.WithLabelValues(method, reason).Inc()
	if !s.failures.allow(ctx, f) {
		unrecordedFailures.WithLabelValues(f.Method).Inc()
		return
	}
	meta := map[string]any{"method": f.Method, "reason": f.Reason}
	if network := httpx.SourceNetwork(f.IP); network != "" {
		meta["network"] = network
	}
	for k, v := range f.Metadata {
		meta[k] = v
	}
	by, resourceType := as(f.Actor, "anonymous", nil), ""
	if f.UserID != uuid.Nil {
		by, resourceType = as(f.Actor, "user", &f.UserID), "user"
	}
	if err := audit.RecordAlone(ctx, s.pool, by.EventIn(orNil(f.OrganizationID), "auth.sign_in_failed", resourceType, f.UserID, meta)); err != nil {
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
	if f.OrganizationID == uuid.Nil && f.UserID != uuid.Nil {
		f.OrganizationID = s.homeOrganization(ctx, f.UserID)
	}
	system, resourceType := as(f.Actor, "system", nil), ""
	if f.UserID != uuid.Nil {
		resourceType = "user"
	}
	for _, lock := range locks {
		if err := audit.RecordAlone(ctx, s.pool, system.EventIn(orNil(f.OrganizationID), "auth.account_locked", resourceType, f.UserID,
			map[string]any{
				"counter": lock.Counter, "network": lock.Network, "failures": lock.Failures, "threshold": lock.Threshold,
				"window_seconds": int(lock.Window.Seconds()), "locked_until": lock.LockedUntil.UTC().Format(time.RFC3339),
			})); err != nil {
			slog.Warn("auth: record a sign-in lock", "counter", lock.Counter, "err", err)
		}
	}
	if throttle != nil {
		if err := audit.RecordAlone(ctx, s.pool, system.EventIn(orNil(f.OrganizationID), "auth.source_throttled", "", uuid.Nil,
			map[string]any{
				"network": throttle.Network, "distinct_accounts": len(throttle.Accounts),
				"window_seconds": int(throttle.Window.Seconds()), "throttled_until": throttle.ThrottledUntil.UTC().Format(time.RFC3339),
			})); err != nil {
			slog.Warn("auth: record a source throttle", "err", err)
		}
	}
}

// homeOrganization is the organization an account belongs to (uuid.Nil: none, or
// it can't be read).
func (s *Service) homeOrganization(ctx context.Context, userID uuid.UUID) uuid.UUID {
	organizationID, err := s.q.HomeOrganization(ctx, userID)
	if err != nil || organizationID == nil {
		return uuid.Nil
	}
	return *organizationID
}

// orNil is an organization as an audit event names its trail: nil (no
// organization's) for uuid.Nil.
func orNil(id uuid.UUID) *uuid.UUID { return postgres.NullIfZero(id) }

// as is from's provenance (client address, user agent, request ID) recorded
// as actorType acting as userID (nil: no one).
func as(from audit.Actor, actorType string, userID *uuid.UUID) audit.Actor {
	from.Type, from.UserID = actorType, userID
	return from
}

// asUser is userID acting on their own account from ip with user agent ua.
func asUser(userID uuid.UUID, ip, ua string) audit.Actor {
	return audit.Actor{UserID: &userID, Type: "user", IP: ip, UserAgent: ua}
}
