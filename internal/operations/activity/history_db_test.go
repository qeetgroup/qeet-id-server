//go:build integration

package activity

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestHistoryPagesThroughEveryEvent checks that following next_cursor returns
// each event exactly once, in order, including events that share a time.
func TestHistoryPagesThroughEveryEvent(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	base := time.Now().Add(-time.Hour)
	var events []auditEvent
	for i := range 8 {
		at := base.Add(time.Duration(i) * time.Second)
		if i < 4 {
			at = base // a run of events at one time spans a page boundary
		}
		events = append(events, insertEvent(t, organization, "user.updated", at))
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, dbtest.Pool(t), NewHub(nil)).Mount)
	if got, want := allPages(t, h, "limit=3"), newestFirst(events); !slices.Equal(got, want) {
		t.Errorf("paged history = %v\nwant %v", got, want)
	}
}

// TestFilteredHistoryReachesOlderMatches checks that a severity filter which
// matches nothing in the newest rows still pages on to older matching events.
func TestFilteredHistoryReachesOlderMatches(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	base := time.Now().Add(-time.Hour)
	var warnings []auditEvent
	for i := range 2 {
		warnings = append(warnings, insertEvent(t, organization, "user.deleted", base.Add(time.Duration(i)*time.Second)))
	}
	for i := range 10 {
		insertEvent(t, organization, "user.created", base.Add(time.Minute+time.Duration(i)*time.Second))
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, dbtest.Pool(t), NewHub(nil)).Mount)
	if got, want := allPages(t, h, "limit=1&min_severity=warning"), newestFirst(warnings); !slices.Equal(got, want) {
		t.Errorf("filtered history = %v, want %v", got, want)
	}
}

// TestSubjectIncludesEventsNamingThePerson checks that a person's timeline and
// summary include events about another resource that name them in
// metadata.user_id, such as being added to a group, and not someone else's.
func TestSubjectIncludesEventsNamingThePerson(t *testing.T) {
	organization := dbtest.Organization(t)
	admin, person, other := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	insert := func(userID string) uuid.UUID {
		id := uuid.New()
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
			INSERT INTO audit.events (id, organization_id, actor_user_id, actor_type, action, resource_type, resource_id, metadata, created_at)
			VALUES ($1, $2, $3, 'user', 'group.member_added', 'group', $4, jsonb_build_object('user_id', $5::text), $6)
		`, id, organization, admin.ID, uuid.New(), userID, at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	added := insert(person.ID.String())
	insert(other.ID.String())
	insert("not-a-uuid") // a malformed value doesn't break the filter

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, dbtest.Pool(t), NewHub(nil)).Mount)
	if got := allPages(t, h, "subject="+person.ID.String()); !slices.Equal(got, []uuid.UUID{added}) {
		t.Errorf("the person's timeline = %v, want their group membership %v", got, added)
	}
	var summary struct {
		Total int64 `json:"total"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/activity/summary?subject="+person.ID.String(), nil), &summary)
	if summary.Total != 1 {
		t.Errorf("the person's summary counts %d events, want 1", summary.Total)
	}
}

// TestHistorySearchTakesWildcardsLiterally checks that _ and % in a search for
// an actor match only themselves.
func TestHistorySearchTakesWildcardsLiterally(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	events := map[string]uuid.UUID{}
	for _, name := range []string{"qa_b", "qaXb", "100%"} {
		actor := dbtest.User(t, organization, organization)
		id := uuid.New()
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET display_name = $2 WHERE id = $1`, actor.ID, name); err != nil {
			t.Fatal(err)
		}
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
			INSERT INTO audit.events (id, organization_id, actor_type, actor_user_id, action, resource_type) VALUES ($1, $2, 'user', $3, 'user.updated', 'user')
		`, id, organization, actor.ID); err != nil {
			t.Fatal(err)
		}
		events[name] = id
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, dbtest.Pool(t), NewHub(nil)).Mount)
	for q, want := range map[string]string{"qa_b": "qa_b", "%": "100%"} {
		if got := allPages(t, h, "q="+url.QueryEscape(q)); !slices.Equal(got, []uuid.UUID{events[want]}) {
			t.Errorf("search %q: %v, want only the event of %q", q, got, want)
		}
	}
}

// TestTheDatabaseClassifiesActionsAsActivityDoes checks that the SQL category
// and severity of every action the code records, and of names made to probe
// each rule, are the ones categoryOf and severityOf give.
func TestTheDatabaseClassifiesActionsAsActivityDoes(t *testing.T) {
	ctx := dbtest.Context(t)
	actions := []string{"threat.x", "a.token_reuse_seen", "x.sign_in_failed", "x.thing_deleted", "x.thing_created", "x.other",
		"unknown.prefix", "auth_hook.created", "admin_portal.link_created"}
	for a := range recordedActions(t) {
		actions = append(actions, a)
	}
	for _, a := range actions {
		var category, severity string
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT audit.activity_category($1), audit.activity_severity($1)`, a).Scan(&category, &severity); err != nil {
			t.Fatal(err)
		}
		if category != categoryOf(a) || severity != severityOf(a) {
			t.Errorf("%s: the database says %s/%s, activity %s/%s; replace the functions in a migration",
				a, category, severity, categoryOf(a), severityOf(a))
		}
	}
}

// TestHistoryFiltersInTheQueryAndCounts checks that resource types, a
// resource, an address, and sets of categories and severities narrow the
// history in the query, that every page but the last is full, and that the
// total is how many match.
func TestHistoryFiltersInTheQueryAndCounts(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	target := uuid.New()
	base := time.Now().Add(-time.Hour)
	insert := func(action, resourceType string, resourceID *uuid.UUID, ip string, at time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO audit.events (id, organization_id, actor_type, action, resource_type, resource_id, ip, created_at)
			VALUES ($1, $2, 'system', $3, $4, $5, NULLIF($6, '')::inet, $7)`, id, organization, action, resourceType, resourceID, ip, at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for i := range 6 {
		insert("user.created", "user", nil, "", base.Add(time.Duration(i)*time.Second))
	}
	deleted := insert("group.deleted", "group", &target, "198.51.100.9", base.Add(time.Minute))
	failed := insert("auth.sign_in_failed", "session", nil, "198.51.100.9", base.Add(2*time.Minute))

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), testHandler(t, dbtest.Pool(t), NewHub(nil)).Mount)
	type page struct {
		Events []struct {
			ID uuid.UUID `json:"id"`
		} `json:"events"`
		Total int `json:"total"`
	}
	get := func(query string) page {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/activity?"+query, nil)
		var p page
		dbtest.Decode(t, rec, &p)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /activity?%s: %d %s", query, rec.Code, rec.Body.String())
		}
		return p
	}
	ids := func(p page) []uuid.UUID {
		out := []uuid.UUID{}
		for _, e := range p.Events {
			out = append(out, e.ID)
		}
		return out
	}
	for query, want := range map[string][]uuid.UUID{
		"resource_type=group,session":       {failed, deleted},
		"resource_id=" + target.String():    {deleted},
		"ip=198.51.100.9":                   {failed, deleted},
		"severity=error,warning":            {failed, deleted},
		"min_severity=error":                {failed},
		"category=directory&severity=error": {},
	} {
		if got := get(query); !slices.Equal(ids(got), want) || got.Total != len(want) {
			t.Errorf("%s: %v of %d, want %v", query, ids(got), got.Total, want)
		}
	}
	if first := get("limit=2&category=directory"); len(first.Events) != 2 || first.Total != 7 {
		t.Errorf("a page of two of the directory events: %d of %d, want 2 of 7", len(first.Events), first.Total)
	}
	for _, bad := range []string{"severity=loud", "category=sales", "resource_id=x", "ip=not-an-ip", "min_severity=high"} {
		if rec := dbtest.Do(t, h, http.MethodGet, "/activity?"+bad, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "bad_request") {
			t.Errorf("%s: %d, want 400", bad, rec.Code)
		}
	}
}
