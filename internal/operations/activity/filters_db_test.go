//go:build integration

package activity

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

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

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount)
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
