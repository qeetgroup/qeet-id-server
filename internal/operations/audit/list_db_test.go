//go:build integration

package audit

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestTheAuditLogIsFilteredAndCounted checks that the audit list narrows by
// several actions and resource types, a resource, an address and a time
// range, carries each event's metadata, and says how many match.
func TestTheAuditLogIsFilteredAndCounted(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	target := uuid.New()
	now := time.Now().UTC()
	insert := func(action, resourceType string, resourceID *uuid.UUID, ip string, at time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO audit.events (id, tenant_id, actor_type, action, resource_type, resource_id, ip, created_at, metadata)
			VALUES ($1, $2, 'system', $3, $4, $5, NULLIF($6, '')::inet, $7, '{"note":"kept"}')`, id, tenant, action, resourceType, resourceID, ip, at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := insert("user.created", "user", nil, "", now.Add(-48*time.Hour))
	group := insert("group.updated", "group", &target, "203.0.113.5", now.Add(-time.Hour))
	role := insert("role.updated", "role", nil, "203.0.113.5", now.Add(-time.Minute))

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Reader: NewReader(dbtest.Pool(t))}).Mount)
	type page struct {
		Items []Row `json:"items"`
		Total int   `json:"total"`
	}
	get := func(v url.Values) page {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/audit?"+v.Encode(), nil)
		var p page
		dbtest.Decode(t, rec, &p)
		if rec.Code != http.StatusOK {
			t.Fatalf("audit %v: %d %s", v, rec.Code, rec.Body.String())
		}
		return p
	}
	ids := func(p page) []uuid.UUID {
		out := []uuid.UUID{}
		for _, r := range p.Items {
			out = append(out, r.ID)
		}
		return out
	}
	for name, c := range map[string]struct {
		query url.Values
		want  []uuid.UUID
	}{
		"several actions":        {url.Values{"action": {"group.updated,role.updated"}}, []uuid.UUID{role, group}},
		"several resource types": {url.Values{"resource_type": {"user,group"}}, []uuid.UUID{group, old}},
		"a resource":             {url.Values{"resource_id": {target.String()}}, []uuid.UUID{group}},
		"an address":             {url.Values{"ip": {"203.0.113.5"}}, []uuid.UUID{role, group}},
		"a time range":           {url.Values{"from": {now.Add(-2 * time.Hour).Format(time.RFC3339)}, "to": {now.Add(-30 * time.Minute).Format(time.RFC3339)}}, []uuid.UUID{group}},
	} {
		if got := get(c.query); !slices.Equal(ids(got), c.want) || got.Total != len(c.want) {
			t.Errorf("%s: %v of %d, want %v", name, ids(got), got.Total, c.want)
		}
	}
	first := get(url.Values{"limit": {"1"}})
	if len(first.Items) != 1 || first.Total != 3 || first.Items[0].Metadata["note"] != "kept" {
		t.Errorf("first page: %+v of %d, want one row with its metadata of 3", first.Items, first.Total)
	}
	for _, bad := range []url.Values{{"ip": {"nope"}}, {"resource_id": {"nope"}}, {"from": {"yesterday"}}} {
		if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/audit?"+bad.Encode(), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("audit %v: %d, want 400", bad, rec.Code)
		}
	}
}
