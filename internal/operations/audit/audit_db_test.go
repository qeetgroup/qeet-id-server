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

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Reader: NewReader(pool), Verifier: NewVerifier(pool)}).Mount)
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

	res, err := NewVerifier(pool).Verify(ctx, &tenantB)
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

	res, err := NewVerifier(dbtest.Pool(t)).Verify(ctx, &tenant)
	if err != nil || !res.OK || res.RowsChecked != 7 {
		t.Fatalf("verify: %+v, %v; want 7 valid rows", res, err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE audit.events SET action = 'user.deleted' WHERE id = $1 AND tenant_id = $2`, ids[5], tenant); err != nil {
		t.Fatal(err)
	}
	res, err = NewVerifier(dbtest.Pool(t)).Verify(ctx, &tenant)
	if err != nil || res.OK || res.BrokenAtID == nil || *res.BrokenAtID != ids[5] || res.RowsChecked != 5 {
		t.Errorf("verify an altered chain: %+v, %v; want broken at %s after 5 rows", res, err, ids[5])
	}
}
