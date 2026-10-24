//go:build integration

package threat

import (
	"testing"
	"time"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestLockoutsCountAsOpenIncidents checks that the anomaly summary counts what
// the sign-in lockouts record (status rate-limited) as open until resolved,
// each affected account once, and critical events as high severity.
func TestLockoutsCountAsOpenIncidents(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	victim := dbtest.User(t, tenant, tenant)
	dbtest.User(t, other, other)

	lock := auth.AccountLock{Email: victim.Email, Network: "203.0.113.0/24", Counter: auth.CounterAccount,
		Reason: "10 failed sign-ins", Failures: 10, Threshold: 10, Window: 15 * time.Minute, LockedUntil: time.Now().Add(15 * time.Minute)}
	svc.OnAccountLocked(ctx, lock)
	svc.OnAccountLocked(ctx, lock)
	if err := svc.Record(ctx, Event{TenantID: tenant, Type: "credential_stuffing", Severity: "critical", Detail: "burst"}); err != nil {
		t.Fatal(err)
	}

	sum, err := svc.Summary(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Open != 3 || sum.AffectedAccounts != 1 || sum.HighSeverity24h != 3 || sum.Resolved24h != 0 {
		t.Errorf("summary %+v, want 3 open (2 rate-limited, 1 open), 1 affected account, 3 high or critical", *sum)
	}
	events, err := svc.List(ctx, tenant, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("list: %d events, %v", len(events), err)
	}
	for _, e := range events {
		if e.UserID != nil {
			if err := svc.Resolve(ctx, e.ID, tenant); err != nil {
				t.Fatal(err)
			}
		}
	}
	if sum, _ = svc.Summary(ctx, tenant); sum.Open != 1 || sum.AffectedAccounts != 0 || sum.Resolved24h != 2 {
		t.Errorf("after resolving the lockouts: %+v, want 1 open, 0 affected, 2 resolved", *sum)
	}
	if sum, _ = svc.Summary(ctx, other); sum.Open != 0 {
		t.Errorf("another organisation's summary: %+v, want nothing", *sum)
	}
}
