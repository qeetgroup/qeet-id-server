//go:build integration

package retention

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// purgeFailures reads retention_user_purge_failures_total.
func purgeFailures(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "retention_user_purge_failures_total" {
			return f.GetMetric()[0].GetCounter().GetValue()
		}
	}
	t.Fatal("retention_user_purge_failures_total is not registered")
	return 0
}

// TestPurgeRemovesEachRipeUser checks that the purge deletes for good every
// deleted account past the window, whatever it sponsored or reviewed; that
// its personal API keys and memberships go with it while its erasure request
// stays, naming it; and that an account something still holds on to is
// skipped and counted, not left to stop the rest.
func TestPurgeRemovesEachRipeUser(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	sponsor, reviewer, held, recent := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization),
		dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	client := dbtest.Unique("app")
	var agent, request uuid.UUID
	for _, s := range []struct {
		sql  string
		args []any
		scan *uuid.UUID
	}{
		{`INSERT INTO auth.agents (organization_id, name, secret_hash, sponsor_user_id) VALUES ($1, 'bot', 'hash', $2) RETURNING id`, []any{organization, sponsor.ID}, &agent},
		{`INSERT INTO auth.oidc_clients (organization_id, client_id, name, reviewed_by, reviewed_at) VALUES ($1, $2, 'Payroll', $3, NOW()) RETURNING id`, []any{organization, client, reviewer.ID}, new(uuid.UUID)},
		{`INSERT INTO auth.api_keys (organization_id, user_id, name, prefix, key_hash) VALUES ($1, $2, 'laptop', $3, 'hash') RETURNING id`, []any{organization, reviewer.ID, dbtest.Unique("qk")}, new(uuid.UUID)},
		{`INSERT INTO account.purge_requests (organization_id, user_id, subject_id, grace_until, status, completed_at) VALUES ($1, $2, $2, NOW(), 'completed', NOW()) RETURNING id`, []any{organization, reviewer.ID}, &request},
	} {
		if err := pool.QueryRow(ctx, s.sql, s.args...).Scan(s.scan); err != nil {
			t.Fatalf("%s: %v", s.sql, err)
		}
	}
	owner := dbtest.Owner(t)
	if _, err := owner.Exec(ctx, `CREATE TABLE public.purge_hold (user_id UUID REFERENCES account.users (id))`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DROP TABLE public.purge_hold`) })
	if _, err := owner.Exec(ctx, `INSERT INTO public.purge_hold VALUES ($1)`, held.ID); err != nil {
		t.Fatal(err)
	}
	for _, u := range []dbtest.Account{sponsor, reviewer, held} {
		if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'deleted', deleted_at = NOW() - INTERVAL '40 days' WHERE id = $1`, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'deleted', deleted_at = NOW() - INTERVAL '2 days' WHERE id = $1`, recent.ID); err != nil {
		t.Fatal(err)
	}

	failures := purgeFailures(t)
	n, err := NewService(pool).PurgeOrganization(ctx, organization, 30)
	if err != nil || n != 2 {
		t.Fatalf("purged %d (%v), want the sponsor and the reviewer", n, err)
	}
	if got := purgeFailures(t) - failures; got != 1 {
		t.Errorf("%v purge failures counted, want the held account's", got)
	}
	for _, c := range []struct {
		what  string
		query string
		arg   any
		want  int
	}{
		{"accounts left", `SELECT count(*) FROM account.users WHERE id = ANY($1)`, []uuid.UUID{sponsor.ID, reviewer.ID, held.ID, recent.ID}, 2},
		{"the agent, without its sponsor", `SELECT count(*) FROM auth.agents WHERE id = $1 AND sponsor_user_id IS NULL`, agent, 1},
		{"the application, without its reviewer", `SELECT count(*) FROM auth.oidc_clients WHERE client_id = $1 AND reviewed_by IS NULL`, client, 1},
		{"the reviewer's personal key", `SELECT count(*) FROM auth.api_keys WHERE organization_id = $1`, organization, 0},
		{"the purged accounts' memberships", `SELECT count(*) FROM rbac.user_roles WHERE user_id = ANY($1)`, []uuid.UUID{sponsor.ID, reviewer.ID}, 0},
		{"the erasure request, naming the account", `SELECT count(*) FROM account.purge_requests WHERE id = $1 AND user_id IS NULL AND subject_id = $2`, nil, 1},
	} {
		args := []any{c.arg}
		if c.arg == nil {
			args = []any{request, reviewer.ID}
		}
		if got := dbtest.Count(t, c.query, args...); got != c.want {
			t.Errorf("%s: %d, want %d", c.what, got, c.want)
		}
	}
}

// TestSweepIsAudited checks that a scheduled sweep that removes people records
// one retention.purge_run event, as the system, with how many and the window,
// and that one that removes nobody records none.
func TestSweepIsAudited(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	svc := NewService(pool)
	if _, err := svc.Update(ctx, organization, Policy{DeletedUsersEnabled: true, DeletedUsersDays: 30}, audit.Actor{Type: "system"}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		u := dbtest.User(t, organization, organization)
		if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'deleted', deleted_at = NOW() - INTERVAL '40 days' WHERE id = $1`, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := svc.sweep(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'retention.purge_run'
		AND actor_type = 'system' AND actor_user_id IS NULL
		AND metadata->>'purged' = '2' AND metadata->>'deleted_users_days' = '30'`, organization); n != 1 {
		t.Errorf("%d purge runs of two people recorded over two sweeps, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'retention.purge_run'`, organization); n != 1 {
		t.Errorf("%d purge runs recorded in all, want only the sweep that removed someone", n)
	}
}

// TestThePolicySaysWhoLastChangedIt checks that the retention policy says
// when it was last changed and by whom.
func TestThePolicySaysWhoLastChangedIt(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: NewService(dbtest.Pool(t))}).Mount)
	path := "/organizations/" + organization.String() + "/retention"
	var p Policy
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &p)
	if p.UpdatedAt != nil || p.UpdatedBy != nil {
		t.Errorf("a policy never set: %+v, want no change recorded", p)
	}
	if rec := dbtest.Do(t, h, http.MethodPut, path, Policy{DeletedUsersEnabled: true, DeletedUsersDays: 45}); rec.Code != http.StatusOK {
		t.Fatalf("set the policy: %d %s", rec.Code, rec.Body.String())
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &p)
	if p.UpdatedAt == nil || p.UpdatedBy == nil || *p.UpdatedBy != admin.ID || p.UpdatedByEmail == nil || *p.UpdatedByEmail != admin.Email {
		t.Errorf("the policy after a change: %+v, want when and by the admin", p)
	}
}

// refuseAudit makes the organization's audit writes of action fail until t
// ends, as an audit store that is down would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	owner, name := dbtest.Owner(t), "refuse_"+strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := owner.Exec(dbtest.Context(t), `
		CREATE FUNCTION pg_temp.`+name+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit store down'; END $$;
		CREATE TRIGGER `+name+` BEFORE INSERT ON audit.events FOR EACH ROW
		WHEN (NEW.organization_id = '`+organization.String()+`' AND NEW.action = '`+action+`') EXECUTE FUNCTION pg_temp.`+name+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(context.Background(), `DROP FUNCTION pg_temp.`+name+`() CASCADE`) })
}

// TestPolicyChangeCommitsWithItsAuditEvent checks that a retention policy
// change is undone when its audit event can't be written, and recorded once,
// as the person who made it, when it can.
func TestPolicyChangeCommitsWithItsAuditEvent(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}
	policy := Policy{DeletedUsersEnabled: true, DeletedUsersDays: 45}

	refuseAudit(t, organization, "retention.policy_updated")
	if _, err := svc.Update(ctx, organization, policy, actor); err == nil {
		t.Fatal("change the policy while its audit event can't be written: no error")
	}
	if p, err := svc.Get(ctx, organization); err != nil || p.DeletedUsersEnabled || p.UpdatedAt != nil {
		t.Errorf("policy after a failed audit write: %+v, %v; want the default", p, err)
	}

	other := dbtest.Organization(t)
	if _, err := svc.Update(ctx, other, policy, actor); err != nil {
		t.Fatal(err)
	}
	if p, err := svc.Get(ctx, other); err != nil || !p.DeletedUsersEnabled || p.DeletedUsersDays != 45 {
		t.Errorf("policy after a change: %+v, %v; want purging after 45 days", p, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'retention.policy_updated'
		AND actor_user_id = $2 AND metadata->>'deleted_users_days' = '45'`, other, admin.ID); n != 1 {
		t.Errorf("%d policy changes recorded as the admin's, want 1", n)
	}
}
