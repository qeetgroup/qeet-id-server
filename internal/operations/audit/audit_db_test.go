//go:build integration

package audit

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// record writes one audit event for tenant and returns its id.
func record(t *testing.T, tenant uuid.UUID, action string) uuid.UUID {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := Record(ctx, tx, Actor{Type: "system"}.Event(tenant, action, "user", uuid.New(), nil)); err != nil {
		t.Fatalf("record %s: %v", action, err)
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit.events WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`, tenant).Scan(&id); err != nil {
		t.Fatalf("read back %s: %v", action, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return id
}

// TestAuditEventsStayInTheirTenant checks that one tenant can neither read nor
// verify another tenant's audit trail, even when it pages from one of its
// event ids.
func TestAuditEventsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminB := dbtest.User(t, tenantB, tenantB)
	eventA := record(t, tenantA, "user.created")
	record(t, tenantA, "user.updated")
	eventB := record(t, tenantB, "user.created")

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Reader: NewReader(pool), Verifier: NewVerifier(pool, nil)}).Mount)
	for _, path := range []string{"/tenants/" + tenantA.String() + "/audit", "/tenants/" + tenantA.String() + "/audit/verify"} {
		if rec := dbtest.Do(t, asB, http.MethodGet, path, nil); rec.Code != http.StatusForbidden {
			t.Errorf("tenant B GET %s: status %d, want 403", path, rec.Code)
		}
	}
	own := "/tenants/" + tenantB.String() + "/audit"
	for _, path := range []string{own, own + "?q=user", own + "?cursor=" + eventA.String()} {
		ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, path, nil))
		if slices.Contains(ids, eventA) {
			t.Errorf("tenant B GET %s returned tenant A's event", path)
		}
		if path == own && !slices.Equal(ids, []uuid.UUID{eventB}) {
			t.Errorf("tenant B's trail = %v, want only %s", ids, eventB)
		}
	}

	res, err := NewVerifier(pool, nil).Verify(ctx, &tenantB)
	if err != nil || !res.OK || res.RowsChecked != 1 {
		t.Errorf("verify tenant B's chain: %+v, %v; want 1 valid row", res, err)
	}
}

// TestAuditListPagesThroughEveryRow checks that following next_cursor returns
// each of the tenant's events exactly once, newest first, including events
// that share a time.
func TestAuditListPagesThroughEveryRow(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	for range 4 {
		record(t, tenant, "user.updated")
	}
	// A run of events at one time, which the id breaks ties between.
	for range 4 {
		if _, err := dbtest.Pool(t).Exec(ctx, `
			INSERT INTO audit.events (tenant_id, actor_type, action, resource_type, created_at)
			VALUES ($1, 'system', 'user.updated', 'user', $2)
		`, tenant, at.Add(-time.Hour)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	var want []uuid.UUID
	rows, err := dbtest.Pool(t).Query(ctx, `SELECT id FROM audit.events WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		want = append(want, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Reader: NewReader(dbtest.Pool(t))}).Mount)
	var got []uuid.UUID
	path := "/tenants/" + tenant.String() + "/audit?limit=3"
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("the audit list did not reach its last page")
		}
		rec := dbtest.Do(t, h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, body %s", path, rec.Code, rec.Body)
		}
		var page struct {
			Items []struct {
				ID uuid.UUID `json:"id"`
			} `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		dbtest.Decode(t, rec, &page)
		for _, item := range page.Items {
			got = append(got, item.ID)
		}
		if page.NextCursor == "" {
			break
		}
		path = "/tenants/" + tenant.String() + "/audit?limit=3&cursor=" + page.NextCursor
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged audit list = %v\nwant %v", got, want)
	}
}

// TestVerifyReadsTheChainInPages checks that verification walks a chain longer
// than one page to its end, and still finds a row altered on a later page.
func TestVerifyReadsTheChainInPages(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	var ids []uuid.UUID
	for range 7 {
		ids = append(ids, record(t, tenant, "user.updated"))
	}
	verifyPageSize = 2
	t.Cleanup(func() { verifyPageSize = 5000 })

	res, err := NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &tenant)
	if err != nil || !res.OK || res.RowsChecked != 7 {
		t.Fatalf("verify: %+v, %v; want 7 valid rows", res, err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.deleted' WHERE id = $1 AND tenant_id = $2`, ids[5], tenant); err != nil {
		t.Fatal(err)
	}
	res, err = NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &tenant)
	if err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != ids[5] || res.RowsChecked != 5 || res.ReasonCode != ChainRowHashMismatch {
		t.Errorf("verify an altered chain: %+v, %v; want broken at %s after 5 rows, its row hash wrong", res, err, ids[5])
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET prev_hash = 'x' WHERE id = $1 AND tenant_id = $2`, ids[2], tenant); err != nil {
		t.Fatal(err)
	}
	res, err = NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &tenant)
	if err != nil || res.BrokenAtID == nil || *res.BrokenAtID != ids[2] || res.ReasonCode != ChainPrevHashMismatch {
		t.Errorf("verify a relinked chain: %+v, %v; want broken at %s, its link wrong", res, err, ids[2])
	}
}

// TestChainSurvivesAnInstanceWhoseClockIsAhead checks that a row written by
// an instance whose clock is behind the chain's tip still goes after it, so
// the chain stays whole when two instances disagree about the time.
func TestChainSurvivesAnInstanceWhoseClockIsAhead(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	clock = func() time.Time { return time.Now().Add(time.Minute) }
	ahead := record(t, tenant, "user.updated")
	clock = time.Now
	t.Cleanup(func() { clock = time.Now })
	behind := record(t, tenant, "user.deleted")

	var first uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM audit.events WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1`, tenant).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first != ahead {
		t.Errorf("the chain starts at %s, want the earlier write %s before %s", first, ahead, behind)
	}
	if res, err := NewVerifier(dbtest.Pool(t), nil).Verify(ctx, &tenant); err != nil || !res.OK || res.RowsChecked != 2 {
		t.Errorf("verify: %+v, %v; want both rows valid", res, err)
	}
}

// TestEventsNameWhatTheyAreAbout checks that an audit row names its resource
// and the role or group its metadata gives an id for, as they are when it is
// written, but never a person, whose name would outlive their erasure; that a
// target already gone keeps the name the caller gave; that another
// organisation's role is not named; that a name the caller gave is kept; and
// that the chain still verifies.
func TestEventsNameWhatTheyAreAbout(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	unnamed := dbtest.User(t, tenant, tenant)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET display_name = 'Asha Rao' WHERE id = $1`, person.ID); err != nil {
		t.Fatal(err)
	}
	var role, otherRole, group, policy uuid.UUID
	for _, q := range []struct {
		dst  *uuid.UUID
		sql  string
		args []any
	}{
		{&role, `INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'auditor') RETURNING id`, []any{tenant}},
		{&otherRole, `INSERT INTO rbac.roles (tenant_id, name) VALUES ($1, 'theirs') RETURNING id`, []any{other}},
		{&group, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Finance') RETURNING id`, []any{tenant}},
		{&policy, `INSERT INTO auth.abac_policies (tenant_id, name, effect, resource_type, action) VALUES ($1, 'office_hours', 'deny', '*', '*') RETURNING id`, []any{tenant}},
	} {
		if err := pool.QueryRow(ctx, q.sql, q.args...).Scan(q.dst); err != nil {
			t.Fatal(err)
		}
	}

	actor := Actor{Type: "system"}
	gone := uuid.New()
	events := []struct {
		event Event
		want  map[string]any
	}{
		{actor.Event(tenant, "role.assigned", "user", person.ID, map[string]any{"role_id": role}),
			map[string]any{"target_name": nil, "role_name": "auditor"}},
		{actor.Event(tenant, "group.member_added", "group", group, map[string]any{"user_id": unnamed.ID.String()}),
			map[string]any{"target_name": "Finance", "user_name": nil}},
		{actor.Event(tenant, "abac_policy.updated", "abac_policy", policy, nil),
			map[string]any{"target_name": "office_hours"}},
		{actor.Event(tenant, "group.deleted", "group", gone, map[string]any{"name": "Old team"}),
			map[string]any{"target_name": "Old team"}},
		{actor.Event(tenant, "role.group_assigned", "group", group, map[string]any{"role_id": otherRole}),
			map[string]any{"target_name": "Finance", "role_name": nil}},
		{actor.Event(tenant, "group.updated", "group", group, map[string]any{"target_name": "as given"}),
			map[string]any{"target_name": "as given"}},
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, e := range events {
		if err := Record(ctx, tx, e.event); err != nil {
			t.Fatalf("record %s: %v", e.event.Action, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, `SELECT metadata FROM audit.events WHERE tenant_id = $1 ORDER BY created_at`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	for rows.Next() {
		var m map[string]any
		if err := rows.Scan(&m); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	if rows.Close(); len(got) != len(events) {
		t.Fatalf("%d rows, want %d", len(got), len(events))
	}
	for i, e := range events {
		for k, want := range e.want {
			if v, ok := got[i][k]; (want == nil && ok) || (want != nil && v != want) {
				t.Errorf("%s: metadata %s = %v, want %v (%v)", e.event.Action, k, v, want, got[i])
			}
		}
	}
	if res, err := NewVerifier(pool, nil).Verify(ctx, &tenant); err != nil || !res.OK {
		t.Errorf("verify the labelled chain: %+v, %v", res, err)
	}
}
