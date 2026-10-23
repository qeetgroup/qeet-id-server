//go:build integration

package risk

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAssessDoesNotRecord checks that assessing a sign-in leaves the history
// unchanged, so a refused or challenged sign-in asked again is assessed the
// same, and that RecordSignIn adds a completed one.
func TestAssessDoesNotRecord(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenant := dbtest.Tenant(t)
	u := dbtest.User(t, tenant, tenant)
	history := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.login_context_history WHERE tenant_id = $1 AND user_id = $2`, tenant, u.ID)
	}

	first := svc.Assess(ctx, tenant, u.ID, "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "IN")
	if again := svc.Assess(ctx, tenant, u.ID, "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "IN"); again != first {
		t.Errorf("the same sign-in assessed again = %v, first %v", again, first)
	}
	if n := history(); n != 0 {
		t.Fatalf("assessing recorded %d sign-ins", n)
	}
	svc.RecordSignIn(ctx, tenant, u.ID, "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "IN")
	if n := history(); n != 1 {
		t.Errorf("RecordSignIn recorded %d sign-ins, want 1", n)
	}
}
