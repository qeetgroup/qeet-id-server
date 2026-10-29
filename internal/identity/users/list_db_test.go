//go:build integration

package user

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestTheMembersListIsSearchedAndCountedOnTheServer checks that each of the
// members list's filters narrows it, that they combine, that the total is how
// many match, that the summary's counts agree with the list, that a
// malformed filter is refused, and that another organisation's people never
// appear.
func TestTheMembersListIsSearchedAndCountedOnTheServer(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var admin uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'admin', TRUE) RETURNING id`, tenant).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	alice := dbtest.UserAt(t, dbtest.Unique("alice")+"@example.test", tenant)
	dbtest.Assign(t, alice.ID, tenant, admin)
	exec(`UPDATE "user".users SET display_name = 'Alice Arden', email_verified_at = NOW(), metadata = '{"department":"Sales"}' WHERE id = $1`, alice.ID)
	exec(`INSERT INTO auth.sessions (user_id, tenant_id, last_seen_at) VALUES ($1, $2, NOW())`, alice.ID, tenant)

	bob := dbtest.UserAt(t, dbtest.Unique("bob")+"@example.test", tenant, tenant)
	exec(`UPDATE "user".users SET display_name = 'Bob Brook', metadata = '{"department":"Engineering"}' WHERE id = $1`, bob.ID)
	exec(`INSERT INTO auth.mfa_totp (user_id, secret, confirmed_at) VALUES ($1, 'secret', NOW())`, bob.ID)

	carol := dbtest.UserAt(t, dbtest.Unique("carol")+"@example.test", tenant, tenant)
	exec(`UPDATE "user".users SET display_name = 'Carol Cole', email_verified_at = NOW(), status = 'suspended' WHERE id = $1`, carol.ID)
	exec(`INSERT INTO auth.sessions (user_id, tenant_id, last_seen_at) VALUES ($1, $2, NOW() - INTERVAL '3 days')`, carol.ID, tenant)

	visitor := dbtest.User(t, other, tenant) // managed by another organisation
	stranger := dbtest.User(t, other, other)

	h := dbtest.Serve(dbtest.Principal(alice.ID, tenant), (&Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}).Mount)
	type page struct {
		Items []User `json:"items"`
		Total int    `json:"total"`
	}
	list := func(query url.Values) page {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/users?"+query.Encode(), nil)
		var p page
		dbtest.Decode(t, rec, &p)
		if rec.Code != http.StatusOK || (query.Get("limit") == "" && p.Total != len(p.Items)) {
			t.Fatalf("list %v: %d %s; want a page as long as its total", query, rec.Code, rec.Body.String())
		}
		return p
	}
	ids := func(p page) map[uuid.UUID]bool {
		out := map[uuid.UUID]bool{}
		for _, u := range p.Items {
			out[u.ID] = true
		}
		return out
	}

	all := list(url.Values{})
	if all.Total != 4 || ids(all)[stranger.ID] {
		t.Fatalf("all members: %d, want the 4 of the organisation and no stranger", all.Total)
	}
	for name, c := range map[string]struct {
		query url.Values
		want  []uuid.UUID
	}{
		"q on the name":         {url.Values{"q": {"ARDEN"}}, []uuid.UUID{alice.ID}},
		"q on the email":        {url.Values{"q": {"bob"}}, []uuid.UUID{bob.ID}},
		"q with a wildcard":     {url.Values{"q": {"%"}}, nil},
		"role":                  {url.Values{"role": {"Admin"}}, []uuid.UUID{alice.ID}},
		"department":            {url.Values{"department": {"engineering"}}, []uuid.UUID{bob.ID}},
		"second factor":         {url.Values{"mfa": {"on"}}, []uuid.UUID{bob.ID}},
		"email not verified":    {url.Values{"email_verified": {"false"}}, []uuid.UUID{bob.ID, visitor.ID}},
		"suspended":             {url.Values{"status": {"suspended"}}, []uuid.UUID{carol.ID}},
		"seen today":            {url.Values{"last_seen": {"today"}}, []uuid.UUID{alice.ID}},
		"seen this week":        {url.Values{"last_seen": {"week"}}, []uuid.UUID{carol.ID}},
		"never seen":            {url.Values{"last_seen": {"never"}}, []uuid.UUID{bob.ID, visitor.ID}},
		"filters together":      {url.Values{"last_seen": {"never"}, "mfa": {"off"}}, []uuid.UUID{visitor.ID}},
		"filters matching none": {url.Values{"role": {"admin"}, "status": {"suspended"}}, nil},
	} {
		got := ids(list(c.query))
		if len(got) != len(c.want) {
			t.Errorf("%s: %d members, want %d", name, len(got), len(c.want))
			continue
		}
		for _, id := range c.want {
			if !got[id] {
				t.Errorf("%s: %s missing", name, id)
			}
		}
	}
	byName := list(url.Values{"sort": {"name"}})
	if byName.Items[0].ID != alice.ID || byName.Items[1].ID != bob.ID || byName.Items[2].ID != carol.ID {
		t.Errorf("sorted by name: %v, want Alice, Bob, Carol first", byName.Items)
	}
	if desc := list(url.Values{"sort": {"name"}, "order": {"desc"}}); desc.Items[len(desc.Items)-1].ID != alice.ID {
		t.Error("sorted by name descending doesn't end with Alice")
	}
	if firstSeen := list(url.Values{"sort": {"last_seen"}}); firstSeen.Items[0].ID != alice.ID {
		t.Error("sorted by last seen doesn't start with the person seen most recently")
	}
	paged := list(url.Values{"limit": {"2"}, "offset": {"2"}})
	if len(paged.Items) != 2 || paged.Total != 4 {
		t.Errorf("second page of two: %d members of %d, want 2 of 4", len(paged.Items), paged.Total)
	}
	if beyond := list(url.Values{"limit": {"2"}, "offset": {"10"}}); len(beyond.Items) != 0 || beyond.Total != 4 {
		t.Errorf("a page past the end: %d members of %d, want none of 4", len(beyond.Items), beyond.Total)
	}
	for _, bad := range []url.Values{{"mfa": {"maybe"}}, {"sort": {"email"}}, {"status": {"deleted"}}, {"last_seen": {"yesterday"}}, {"order": {"up"}}} {
		if rec := dbtest.Do(t, h, http.MethodGet, "/users?"+bad.Encode(), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("list %v: %d, want 400", bad, rec.Code)
		}
	}

	var stats struct {
		Total            int            `json:"total"`
		LastSeen         map[string]int `json:"last_seen"`
		AdminsWithoutMFA int            `json:"admins_without_mfa"`
		EmailUnverified  int            `json:"email_unverified"`
		ByRole           []RoleCount    `json:"by_role"`
		ByDepartment     []DeptCount    `json:"by_department"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/users/stats", nil), &stats)
	for bucket, n := range stats.LastSeen {
		if want := list(url.Values{"last_seen": {bucket}}).Total; n != want {
			t.Errorf("stats last_seen.%s = %d, the list's total %d", bucket, n, want)
		}
	}
	if stats.Total != 4 || stats.AdminsWithoutMFA != 1 || stats.EmailUnverified != list(url.Values{"email_verified": {"false"}}).Total {
		t.Errorf("stats %+v", stats)
	}
	if len(stats.ByRole) == 0 || len(stats.ByDepartment) != 2 {
		t.Errorf("stats by role %v, by department %v", stats.ByRole, stats.ByDepartment)
	}
}

// TestAMembersRecordSaysWhereTheyStand checks that a member's own record has
// their roles with IDs, second factor, last sight, the organisation managing
// them and, for the organisation's own suspended people, the suspension.
func TestAMembersRecordSaysWhereTheyStand(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	visitor := dbtest.User(t, other, tenant)
	suspended := dbtest.User(t, tenant, tenant)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit.events (tenant_id, actor_user_id, actor_type, action, resource_type, resource_id)
		VALUES ($1, $2, 'user', 'user.suspended', 'user', $3)`, tenant, admin.ID, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions (user_id, tenant_id, last_seen_at, ip) VALUES ($1, $2, NOW(), '198.51.100.4')`, visitor.ID, tenant); err != nil {
		t.Fatal(err)
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}).Mount)

	var got User
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/users/"+visitor.ID.String(), nil), &got)
	var otherName string
	if err := pool.QueryRow(ctx, `SELECT name FROM tenant.tenants WHERE id = $1`, other).Scan(&otherName); err != nil {
		t.Fatal(err)
	}
	if len(got.AssignedRoles) != 1 || got.AssignedRoles[0].ID == uuid.Nil || len(got.Roles) != 1 || got.MfaEnabled == nil || *got.MfaEnabled ||
		got.LastSeenAt == nil || got.LastSeenIP == nil || *got.LastSeenIP != "198.51.100.4" || got.HomeTenantName == nil || *got.HomeTenantName != otherName {
		t.Errorf("a visiting member's record: %+v", got)
	}
	if got.Suspension != nil {
		t.Errorf("an active member's suspension: %+v", got.Suspension)
	}

	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/users/"+suspended.ID.String(), nil), &got)
	s := got.Suspension
	if s == nil || s.SuspendedAt == nil || s.SuspendedBy == nil || *s.SuspendedBy != admin.ID || s.SuspendedByEmail == nil || *s.SuspendedByEmail != admin.Email {
		t.Errorf("a suspended member's suspension: %+v, want when and by the admin", s)
	}
}
