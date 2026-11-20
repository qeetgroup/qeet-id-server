//go:build integration

package user

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// TestTheMembersListIsSearchedAndCountedOnTheServer checks that each of the
// members list's filters narrows it, among them the owners and admins without
// a second factor and the members in none of the organization's groups (not
// another organization's), that they combine, that the total is how many
// match, that it pages by cursor alone, that the summary's counts agree with
// the list, that a malformed filter is refused, and that another
// organization's people never appear.
func TestTheMembersListIsSearchedAndCountedOnTheServer(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var admin uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'admin', TRUE) RETURNING id`, organization).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	alice := dbtest.UserAt(t, dbtest.Unique("alice")+"@example.test", organization)
	dbtest.Assign(t, alice.ID, organization, admin)
	exec(`UPDATE account.users SET display_name = 'Alice Arden', email_verified_at = NOW(), metadata = '{"department":"Sales"}' WHERE id = $1`, alice.ID)
	exec(`INSERT INTO auth.sessions (user_id, organization_id, last_seen_at) VALUES ($1, $2, NOW())`, alice.ID, organization)

	bob := dbtest.UserAt(t, dbtest.Unique("bob")+"@example.test", organization, organization)
	exec(`UPDATE account.users SET display_name = 'Bob Brook', metadata = '{"department":"Engineering"}' WHERE id = $1`, bob.ID)
	exec(`INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce, confirmed_at) VALUES ($1, '\x00', '\x00', NOW())`, bob.ID)

	carol := dbtest.UserAt(t, dbtest.Unique("carol")+"@example.test", organization, organization)
	exec(`UPDATE account.users SET display_name = 'Carol Cole', email_verified_at = NOW(), status = 'suspended' WHERE id = $1`, carol.ID)
	exec(`INSERT INTO auth.sessions (user_id, organization_id, last_seen_at) VALUES ($1, $2, NOW() - INTERVAL '3 days')`, carol.ID, organization)

	visitor := dbtest.User(t, other, organization) // managed by another organization
	stranger := dbtest.User(t, other, other)
	for _, in := range []struct {
		organization uuid.UUID
		member       uuid.UUID
	}{{organization, carol.ID}, {other, visitor.ID}} {
		exec(`WITH g AS (INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id)
			INSERT INTO organization.group_members (group_id, user_id, organization_id) SELECT id, $3, $1 FROM g`,
			in.organization, dbtest.Unique("group"), in.member)
	}

	h := dbtest.Serve(dbtest.Principal(alice.ID, organization), (&Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator(), SignIns: endSessions{}, Mailer: &dbtest.Mailbox{}}).Mount)
	type page struct {
		Items      []User `json:"items"`
		NextCursor string `json:"next_cursor"`
		Total      int    `json:"total"`
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
		t.Fatalf("all members: %d, want the 4 of the organization and no stranger", all.Total)
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
		"admins without MFA":    {url.Values{"admins_without_mfa": {"true"}}, []uuid.UUID{alice.ID}},
		"not admins without":    {url.Values{"admins_without_mfa": {"false"}}, []uuid.UUID{bob.ID, carol.ID, visitor.ID}},
		"in a group":            {url.Values{"in_group": {"true"}}, []uuid.UUID{carol.ID}},
		"in no group":           {url.Values{"in_group": {"false"}}, []uuid.UUID{alice.ID, bob.ID, visitor.ID}},
		"in no group, with MFA": {url.Values{"in_group": {"false"}, "mfa": {"on"}}, []uuid.UUID{bob.ID}},
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
	first := list(url.Values{"limit": {"2"}})
	if len(first.Items) != 2 || first.Total != 4 || first.NextCursor == "" {
		t.Fatalf("first page of two: %d members of %d, cursor %q; want 2 of 4 and a cursor", len(first.Items), first.Total, first.NextCursor)
	}
	last := dbtest.Do(t, h, http.MethodGet, "/users?"+url.Values{"limit": {"2"}, "cursor": {first.NextCursor}}.Encode(), nil)
	var second page
	dbtest.Decode(t, last, &second)
	if len(second.Items) != 2 || second.Total != 4 || ids(second)[first.Items[0].ID] || ids(second)[first.Items[1].ID] {
		t.Errorf("second page of two: %v of %d, want the other 2 of 4", ids(second), second.Total)
	}
	if body := last.Body.String(); strings.Contains(body, "next_cursor") {
		t.Errorf("the last page: %s, want no next_cursor", body)
	}
	// offset is no parameter: it never skips anyone.
	if skipped := list(url.Values{"limit": {"2"}, "offset": {"2"}}); len(skipped.Items) != 2 || skipped.Items[0].ID != first.Items[0].ID {
		t.Errorf("offset=2 lists %v, want the first page %v", ids(skipped), ids(first))
	}
	for _, bad := range []url.Values{{"mfa": {"maybe"}}, {"sort": {"email"}}, {"status": {"deleted"}}, {"last_seen": {"yesterday"}}, {"order": {"up"}},
		{"admins_without_mfa": {"maybe"}}, {"in_group": {"none"}}} {
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
	if stats.Total != 4 || stats.AdminsWithoutMFA != list(url.Values{"admins_without_mfa": {"true"}}).Total || stats.EmailUnverified != list(url.Values{"email_verified": {"false"}}).Total {
		t.Errorf("stats %+v", stats)
	}
	if len(stats.ByRole) == 0 || len(stats.ByDepartment) != 2 {
		t.Errorf("stats by role %v, by department %v", stats.ByRole, stats.ByDepartment)
	}
}

// TestAMembersRecordSaysWhereTheyStand checks that a member's own record has
// their roles with IDs, second factor, last sight, the organization managing
// them and, for the organization's own suspended people, the suspension.
func TestAMembersRecordSaysWhereTheyStand(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	visitor := dbtest.User(t, other, organization)
	suspended := dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit.events (organization_id, actor_user_id, actor_type, action, resource_type, resource_id)
		VALUES ($1, $2, 'user', 'user.suspended', 'user', $3)`, organization, admin.ID, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions (user_id, organization_id, last_seen_at, ip) VALUES ($1, $2, NOW(), '198.51.100.4')`, visitor.ID, organization); err != nil {
		t.Fatal(err)
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator(), SignIns: endSessions{}, Mailer: &dbtest.Mailbox{}}).Mount)

	var got User
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/users/"+visitor.ID.String(), nil), &got)
	var otherName string
	if err := pool.QueryRow(ctx, `SELECT name FROM organization.organizations WHERE id = $1`, other).Scan(&otherName); err != nil {
		t.Fatal(err)
	}
	if len(got.AssignedRoles) != 1 || got.AssignedRoles[0].ID == uuid.Nil || len(got.Roles) != 1 || got.MfaEnabled == nil || *got.MfaEnabled ||
		got.LastSeenAt == nil || got.LastSeenIP == nil || *got.LastSeenIP != "198.51.100.4" || got.HomeOrganizationName == nil || *got.HomeOrganizationName != otherName {
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

// TestListPagesThroughTheOrganizationsMembers checks that the user list walks
// every live member of the caller's organization exactly once by cursor,
// leaves out other organizations' people and deleted accounts, and shows a
// member's roles and groups in this organization only.
func TestListPagesThroughTheOrganizationsMembers(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	want := []uuid.UUID{admin.ID}
	for range 4 {
		want = append(want, dbtest.User(t, organization, organization).ID)
	}
	guest := dbtest.User(t, other, other, organization)
	want = append(want, guest.ID)
	outsider := dbtest.User(t, other, other)
	gone := dbtest.User(t, organization, organization)
	exec(t, `UPDATE account.users SET deleted_at = NOW(), status = 'deleted' WHERE id = $1`, gone.ID)
	for _, in := range []uuid.UUID{organization, other} {
		exec(t, `
			WITH g AS (INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id)
			INSERT INTO organization.group_members (group_id, user_id, organization_id) SELECT id, $3, $1 FROM g
		`, in, dbtest.Unique("group"), guest.ID)
	}
	exec(t, `INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce, confirmed_at) VALUES ($1, '\x00', '\x00', NOW())`, admin.ID)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)

	var walked []User
	cursor := ""
	for page := 1; ; page++ {
		if page > 3 {
			t.Fatal("the cursor walk didn't end")
		}
		path := "/users?limit=4"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		rec := dbtest.Do(t, as, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list page %d: status %d (%s)", page, rec.Code, rec.Body.String())
		}
		var body struct {
			Items      []User `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		dbtest.Decode(t, rec, &body)
		if page == 1 && len(body.Items) != 4 {
			t.Errorf("the first page has %d users, want 4", len(body.Items))
		}
		walked = append(walked, body.Items...)
		if body.NextCursor == "" {
			break
		}
		cursor = body.NextCursor
	}
	var got []uuid.UUID
	for _, u := range walked {
		got = append(got, u.ID)
	}
	if !slices.Equal(slices.SortedFunc(slices.Values(got), uuidCompare), slices.SortedFunc(slices.Values(want), uuidCompare)) {
		t.Errorf("the cursor walk listed %v, want each of %v once (not %s or %s)", got, want, outsider.ID, gone.ID)
	}

	if ids := dbtest.IDs(t, dbtest.Do(t, as, http.MethodGet, "/users?limit=2&offset=2", nil)); len(got) == len(want) && !slices.Equal(ids, got[:2]) {
		t.Errorf("offset=2 lists %v, want the first page %v: the list pages by cursor alone", ids, got[:2])
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users?limit=2&sort=name&cursor="+url.QueryEscape(paging.EncodeTimeUUID(time.Now(), admin.ID)), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("the default order's cursor in the name order: %d, want 400", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users?cursor=not-a-cursor", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("list with a bad cursor: %d, want 400", rec.Code)
	}

	var roleHere string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT r.name FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.organization_id = $2
	`, guest.ID, organization).Scan(&roleHere); err != nil {
		t.Fatal(err)
	}
	for _, u := range walked {
		if u.ID != guest.ID {
			continue
		}
		if !slices.Equal(u.Roles, []string{roleHere}) {
			t.Errorf("the guest's roles are listed as %v, want only %q from this organization", u.Roles, roleHere)
		}
		if u.GroupsCount == nil || *u.GroupsCount != 1 {
			t.Errorf("the guest's groups are counted as %v, want 1 in this organization", u.GroupsCount)
		}
	}

	var stats UserStats
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users/stats", nil), &stats)
	if stats != (UserStats{Total: 6, Active: 6, MFAEnabled: 1, MFAMissing: 5, NewLast30d: 6}) {
		t.Errorf("stats %+v, want 6 active members, 1 with a second factor", stats)
	}
	var trends UserTrends
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users/trends", nil), &trends)
	if len(trends.Total) != 30 || len(trends.MFAEnabled) != 30 || trends.Total[29] != 6 || trends.MFAEnabled[29] != 1 {
		t.Errorf("trends %+v, want 30 days ending at 6 members, 1 with a second factor", trends)
	}
}

// TestListShowsOnlyTheOrganizationsLastSignIn checks that the user list shows
// when and from where a member last used this organization, not another one.
func TestListShowsOnlyTheOrganizationsLastSignIn(t *testing.T) {
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	guest := dbtest.User(t, home, home, organization)
	session(t, guest.ID, home, "198.51.100.7")
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	var page struct {
		Items []User `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users", nil), &page)
	for _, u := range page.Items {
		if u.ID != guest.ID || (u.LastSeenIP == nil && u.LastSeenAt == nil) {
			continue
		}
		ip := ""
		if u.LastSeenIP != nil {
			ip = *u.LastSeenIP
		}
		t.Errorf("another organization sees the member's last sign-in there: at %v from %q", u.LastSeenAt, ip)
	}
}

// TestLastSignInOutlastsTheSessions checks that the user list and the
// suspended list still show when and from where someone last signed in to the
// organization once their sessions are gone, from the sign-in log, and never a
// sign-in to another organization.
func TestLastSignInOutlastsTheSessions(t *testing.T) {
	ctx := dbtest.Context(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	member := dbtest.User(t, organization, organization, other)
	signIn := func(org uuid.UUID, ago time.Duration, ip string) {
		t.Helper()
		if _, err := dbtest.Pool(t).Exec(ctx, `
			INSERT INTO audit.events (organization_id, actor_user_id, actor_type, action, resource_type, ip, created_at)
			VALUES ($1, $2, 'user', 'auth.login_succeeded', 'session', $3::inet, NOW() - $4::interval)`,
			org, member.ID, ip, ago.String()); err != nil {
			t.Fatal(err)
		}
	}
	signIn(organization, 20*24*time.Hour, "203.0.113.9")
	signIn(other, 2*24*time.Hour, "198.51.100.40")

	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	var page struct {
		Items []User `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, as, http.MethodGet, "/users", nil), &page)
	i := slices.IndexFunc(page.Items, func(u User) bool { return u.ID == member.ID })
	if i < 0 {
		t.Fatal("the member isn't listed")
	}
	got := page.Items[i]
	if got.LastSeenAt == nil || time.Since(*got.LastSeenAt) < 19*24*time.Hour || time.Since(*got.LastSeenAt) > 21*24*time.Hour ||
		got.LastSeenIP == nil || *got.LastSeenIP != "203.0.113.9" {
		t.Errorf("last seen %v from %v, want the sign-in here 20 days ago from 203.0.113.9", got.LastSeenAt, got.LastSeenIP)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1 AND organization_id = $2`, member.ID, organization); err != nil {
		t.Fatal(err)
	}
	suspended, err := testHandler(t, nil).Repo.ListSuspended(ctx, organization, SuspensionFilters{Limit: 10})
	if err != nil || len(suspended.Items) != 1 || suspended.Items[0].LastSignIn == nil ||
		time.Since(*suspended.Items[0].LastSignIn) < 19*24*time.Hour {
		t.Errorf("suspended list %+v, %v; want the member, last signed in here 20 days ago", suspended.Items, err)
	}
}

// TestEveryOrderPagesToTheEnd checks that the members list pages by cursor in
// every order, by name, by when last seen and by creation, each either way:
// small pages walk every member once, in the order one page of all of them
// has, though names, sightings and creation times tie and some members were
// never seen. A cursor from a page in another order is refused.
func TestEveryOrderPagesToTheEnd(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	members := []uuid.UUID{admin.ID}
	seen := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	created := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	for i := range 9 {
		u := dbtest.User(t, organization, organization)
		members = append(members, u.ID)
		// Three people to a name, three to a moment, and a third never seen.
		exec(t, `UPDATE account.users SET display_name = $2, created_at = $3 WHERE id = $1`,
			u.ID, []string{"Asha", "Ravi", ""}[i%3], created.Add(time.Duration(i/3)*time.Hour))
		if i%3 != 2 {
			exec(t, `INSERT INTO auth.sessions (user_id, organization_id, last_seen_at) VALUES ($1, $2, $3)`,
				u.ID, organization, seen.Add(time.Duration(i%2)*time.Minute))
		}
	}
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	type page struct {
		Items      []User `json:"items"`
		NextCursor string `json:"next_cursor"`
		Total      int    `json:"total"`
	}
	get := func(query url.Values) page {
		t.Helper()
		rec := dbtest.Do(t, as, http.MethodGet, "/users?"+query.Encode(), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list %v: %d %s", query, rec.Code, rec.Body.String())
		}
		var p page
		dbtest.Decode(t, rec, &p)
		return p
	}
	ids := func(users []User) []uuid.UUID {
		out := make([]uuid.UUID, len(users))
		for i, u := range users {
			out[i] = u.ID
		}
		return out
	}

	cursors := map[string]string{}
	for _, order := range []url.Values{
		{"sort": {"name"}}, {"sort": {"name"}, "order": {"desc"}},
		{"sort": {"last_seen"}}, {"sort": {"last_seen"}, "order": {"asc"}},
		{"sort": {"created"}, "order": {"asc"}}, {"sort": {"created"}},
	} {
		all := get(url.Values{"sort": order["sort"], "order": order["order"], "limit": {"200"}})
		if len(all.Items) != len(members) || all.NextCursor != "" {
			t.Fatalf("%v in one page: %d members, cursor %q; want all %d and no cursor", order, len(all.Items), all.NextCursor, len(members))
		}
		var walked []User
		cursor := ""
		for range len(members) {
			query := url.Values{"sort": order["sort"], "order": order["order"], "limit": {"2"}}
			if cursor != "" {
				query.Set("cursor", cursor)
			}
			p := get(query)
			if p.Total != len(members) {
				t.Errorf("%v: a page's total %d, want %d", order, p.Total, len(members))
			}
			walked = append(walked, p.Items...)
			if cursor = p.NextCursor; cursor == "" {
				break
			}
			cursors[order.Encode()] = cursor
		}
		if !slices.Equal(ids(walked), ids(all.Items)) {
			t.Errorf("%v walked two at a time:\n%v\nwant the one page's order:\n%v", order, ids(walked), ids(all.Items))
		}
	}
	for _, order := range []string{"last_seen", "last_seen&order=asc"} {
		q, _ := url.ParseQuery("sort=" + order + "&limit=200")
		items := get(q).Items
		if last := items[len(items)-1]; last.LastSeenAt != nil {
			t.Errorf("%s: the last member was seen at %v, want one never seen", order, last.LastSeenAt)
		}
	}

	nameCursor := cursors[url.Values{"sort": {"name"}}.Encode()]
	for _, bad := range []url.Values{
		{"sort": {"name"}, "order": {"desc"}, "cursor": {nameCursor}},
		{"sort": {"last_seen"}, "cursor": {nameCursor}},
		{"cursor": {nameCursor}},
		{"sort": {"name"}, "cursor": {cursors[url.Values{"sort": {"created"}}.Encode()]}},
		{"sort": {"name"}, "cursor": {"not-a-cursor"}},
	} {
		if rec := dbtest.Do(t, as, http.MethodGet, "/users?"+bad.Encode(), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("list %v: %d, want 400", bad, rec.Code)
		}
	}
}

// TestTheListNamesMembersByIDOrEmail checks that the members list answers
// exactly the members named by id or by email (in any case), combined with the
// other filters, never another organization's people, and someone since
// deleted only when asked to include them, marked as deleted. Too many names,
// or a malformed one, is refused.
func TestTheListNamesMembersByIDOrEmail(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asha := dbtest.UserAt(t, dbtest.Unique("Asha")+"@Example.test", organization, organization)
	ravi := dbtest.User(t, organization, organization)
	exec(t, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, ravi.ID)
	visitor := dbtest.User(t, other, organization)
	stranger := dbtest.User(t, other, other)
	gone := dbtest.User(t, organization, organization)
	exec(t, `UPDATE account.users SET deleted_at = NOW(), status = 'deleted' WHERE id = $1`, gone.ID)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, nil).Mount)
	type page struct {
		Items []User `json:"items"`
		Total int    `json:"total"`
	}
	list := func(query url.Values) page {
		t.Helper()
		rec := dbtest.Do(t, as, http.MethodGet, "/users?"+query.Encode(), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list %v: %d %s", query, rec.Code, rec.Body.String())
		}
		var p page
		dbtest.Decode(t, rec, &p)
		return p
	}
	sorted := func(p page) []uuid.UUID {
		out := make([]uuid.UUID, 0, len(p.Items))
		for _, u := range p.Items {
			out = append(out, u.ID)
		}
		return slices.SortedFunc(slices.Values(out), uuidCompare)
	}
	want := func(ids ...uuid.UUID) []uuid.UUID { return slices.SortedFunc(slices.Values(ids), uuidCompare) }

	for name, c := range map[string]struct {
		query url.Values
		want  []uuid.UUID
	}{
		"two by id":                    {url.Values{"id": {asha.ID.String(), visitor.ID.String()}}, want(asha.ID, visitor.ID)},
		"by id, with a filter":         {url.Values{"id": {asha.ID.String(), ravi.ID.String()}, "status": {"suspended"}}, want(ravi.ID)},
		"another organization's by id": {url.Values{"id": {stranger.ID.String()}}, nil},
		"by email, in another case":    {url.Values{"email": {strings.ToUpper(asha.Email), ravi.Email}}, want(asha.ID, ravi.ID)},
		"another organization's email": {url.Values{"email": {stranger.Email}}, nil},
		"by id and by email":           {url.Values{"id": {asha.ID.String()}, "email": {asha.Email, ravi.Email}}, want(asha.ID)},
		"someone deleted":              {url.Values{"id": {gone.ID.String()}}, nil},
		"someone deleted, asked for":   {url.Values{"id": {gone.ID.String(), asha.ID.String()}, "include_deleted": {"true"}}, want(gone.ID, asha.ID)},
	} {
		p := list(c.query)
		if got := sorted(p); !slices.Equal(got, c.want) || p.Total != len(c.want) {
			t.Errorf("%s: %v (total %d), want %v", name, got, p.Total, c.want)
		}
	}

	everyone := list(url.Values{"include_deleted": {"true"}, "limit": {"200"}})
	if got := sorted(everyone); !slices.Equal(got, want(admin.ID, asha.ID, ravi.ID, visitor.ID, gone.ID)) {
		t.Errorf("everyone, the deleted included: %v", got)
	}
	for _, u := range everyone.Items {
		if (u.ID == gone.ID) != (u.DeletedAt != nil) || u.ID == gone.ID && u.Status != "deleted" {
			t.Errorf("%s is marked deleted at %v with status %s; want only the deleted person marked", u.ID, u.DeletedAt, u.Status)
		}
	}
	if body := dbtest.Do(t, as, http.MethodGet, "/users", nil).Body.String(); strings.Contains(body, "deleted_at") || strings.Contains(body, gone.ID.String()) {
		t.Errorf("the list without include_deleted: %s; want no one deleted", body)
	}

	many := url.Values{}
	for range 201 {
		many.Add("id", uuid.NewString())
	}
	for _, bad := range []url.Values{many, {"id": {"not-an-id"}}, {"email": {" "}}, {"include_deleted": {"maybe"}}} {
		if rec := dbtest.Do(t, as, http.MethodGet, "/users?"+bad.Encode(), nil); rec.Code != http.StatusBadRequest {
			t.Errorf("list with %.80s: %d, want 400", bad.Encode(), rec.Code)
		}
	}
}
