//go:build integration

package authentication

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// atSessionLimit caps a's sessions in organization at one, refusing a sign-in beyond
// it, and opens that one session.
func atSessionLimit(t *testing.T, svc *Service, a dbtest.Account, organization uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO organization.security_policies (organization_id, max_sessions, session_limit_action) VALUES ($1, 1, 'refuse')
	`, organization); err != nil {
		t.Fatalf("session limit: %v", err)
	}
	if _, err := svc.IssuePair(dbtest.Context(t), a.ID, organization, "", "test", "password"); err != nil {
		t.Fatalf("first session: %v", err)
	}
}

// sessionLimitRefusals counts the recorded refusals of a's sign-ins at the
// session limit.
func sessionLimitRefusals(t *testing.T, a dbtest.Account) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_refused_session_limit' AND resource_id = $1`, a.ID)
}

// TestSessionLimitRefusalWithOneConnection checks that a sign-in refused at
// the organization's session limit is refused, and recorded, with only one
// connection free.
func TestSessionLimitRefusalWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, organization := member(t)
	atSessionLimit(t, svc, a, organization)

	dbtest.LeaveOneConnection(t)
	if _, err := svc.IssuePair(ctx, a.ID, organization, "", "test", "password"); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("sign in beyond the limit: %v, want %v", err, ErrSessionLimit)
	}
	if n := sessionLimitRefusals(t, a); n != 1 {
		t.Errorf("the refusal was recorded %d times, want 1", n)
	}
}

// TestConcurrentSessionLimitRefusals checks that more sign-ins beyond the
// session limit than the pool has connections, run at once, are all refused
// and recorded.
func TestConcurrentSessionLimitRefusals(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, organization := member(t)
	atSessionLimit(t, svc, a, organization)
	n := 3 * int(dbtest.Pool(t).Config().MaxConns)

	for i, err := range concurrently(n, func(int) error {
		_, err := svc.IssuePair(ctx, a.ID, organization, "", "test", "password")
		return err
	}) {
		if !errors.Is(err, ErrSessionLimit) {
			t.Errorf("sign-in %d beyond the limit: %v, want %v", i, err, ErrSessionLimit)
		}
	}
	if got := sessionLimitRefusals(t, a); got != n {
		t.Errorf("%d refusals recorded, want %d", got, n)
	}
}
