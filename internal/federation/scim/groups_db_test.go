//go:build integration

package scim

// Database tests for SCIM groups and users, driving the real handlers through
// MountPublic against a migrated PostgreSQL (see dbtest).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func memberValues(res map[string]any) []string {
	raw, _ := res["members"].([]any)
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		if mm, ok := m.(map[string]any); ok {
			if v, ok := mm["value"].(string); ok {
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestSCIMGroupLifecycle walks create → get → list → PATCH add member →
// PATCH remove member → delete, plus the displayName filter.
func TestSCIMGroupLifecycle(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	alice := f.seedUser(t, ctx, "alice-"+uuid.NewString()+"@acme.test")
	bob := f.seedUser(t, ctx, "bob-"+uuid.NewString()+"@acme.test")

	// --- create (displayName + one initial member) ---
	rec := f.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "Engineering",
		"externalId":  "ext-eng-1",
		"members":     []map[string]any{{"value": alice.String()}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	created := decodeBody(t, rec)
	gid, _ := created["id"].(string)
	if gid == "" {
		t.Fatalf("create: missing id, body %s", rec.Body.String())
	}
	if created["displayName"] != "Engineering" {
		t.Fatalf("create: displayName = %v", created["displayName"])
	}
	if created["externalId"] != "ext-eng-1" {
		t.Fatalf("create: externalId = %v", created["externalId"])
	}
	if got := memberValues(created); len(got) != 1 || got[0] != alice.String() {
		t.Fatalf("create: members = %v, want [%s]", got, alice)
	}

	// --- get ---
	rec = f.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d", rec.Code)
	}
	got := decodeBody(t, rec)
	if got["displayName"] != "Engineering" {
		t.Fatalf("get: displayName = %v", got["displayName"])
	}

	// --- list + displayName filter ---
	rec = f.do(t, http.MethodGet, `/scim/v2/Groups?filter=`+urlFilter("Engineering"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status %d", rec.Code)
	}
	list := decodeBody(t, rec)
	if total, _ := list["totalResults"].(float64); total != 1 {
		t.Fatalf("filtered list totalResults = %v, want 1", list["totalResults"])
	}
	// A non-matching filter returns zero.
	rec = f.do(t, http.MethodGet, `/scim/v2/Groups?filter=`+urlFilter("Nope"), nil)
	nope := decodeBody(t, rec)
	if total, _ := nope["totalResults"].(float64); total != 0 {
		t.Fatalf("non-matching filter totalResults = %v, want 0", nope["totalResults"])
	}

	// --- PATCH add member (Okta-style add op) ---
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": bob.String()}}}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch add: status %d body %s", rec.Code, rec.Body.String())
	}
	afterAdd := memberValues(decodeBody(t, rec))
	want := []string{alice.String(), bob.String()}
	sort.Strings(want)
	if len(afterAdd) != 2 || afterAdd[0] != want[0] || afterAdd[1] != want[1] {
		t.Fatalf("patch add: members = %v, want %v", afterAdd, want)
	}

	// --- PATCH remove member (Okta filter-path remove) ---
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + alice.String() + `"]`}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch remove: status %d body %s", rec.Code, rec.Body.String())
	}
	afterRemove := memberValues(decodeBody(t, rec))
	if len(afterRemove) != 1 || afterRemove[0] != bob.String() {
		t.Fatalf("patch remove: members = %v, want [%s]", afterRemove, bob)
	}

	// --- PATCH replace displayName ---
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Eng Renamed"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch rename: status %d", rec.Code)
	}
	if decodeBody(t, rec)["displayName"] != "Eng Renamed" {
		t.Fatalf("patch rename did not take")
	}

	// --- delete ---
	rec = f.do(t, http.MethodDelete, "/scim/v2/Groups/"+gid, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", rec.Code)
	}
	rec = f.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", rec.Code)
	}
}

// TestSCIMGroupNameUniqueness checks that groups with an externalId may share
// a displayName, and that a group without one which takes an existing name,
// ignoring case, is refused with 409 uniqueness on create, replace and patch.
func TestSCIMGroupNameUniqueness(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Support')`, f.organizationID); err != nil {
		t.Fatalf("seed console group: %v", err)
	}
	create := func(name, externalID string) *httptest.ResponseRecorder {
		body := map[string]any{"schemas": []string{schemaGroup}, "displayName": name}
		if externalID != "" {
			body["externalId"] = externalID
		}
		return f.do(t, http.MethodPost, "/scim/v2/Groups", body)
	}
	isUniqueness := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusConflict && decodeBody(t, rec)["scimType"] == "uniqueness"
	}

	var ids []string
	for _, ext := range []string{"ext-1", "ext-2"} {
		rec := create("Marketing", ext)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create Marketing %s: status %d body %s", ext, rec.Code, rec.Body)
		}
		id, _ := decodeBody(t, rec)["id"].(string)
		ids = append(ids, id)
	}
	if rec := create("support", ""); !isUniqueness(rec) {
		t.Errorf("create support without externalId: status %d body %s, want 409 uniqueness", rec.Code, rec.Body)
	}

	rec := f.do(t, http.MethodPut, "/scim/v2/Groups/"+ids[0], map[string]any{
		"schemas": []string{schemaGroup}, "displayName": "SUPPORT",
	})
	if !isUniqueness(rec) {
		t.Errorf("replace as SUPPORT without externalId: status %d body %s, want 409 uniqueness", rec.Code, rec.Body)
	}

	clearExternalID := func(id string) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPatch, "/scim/v2/Groups/"+id, map[string]any{
			"schemas":    []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "replace", "path": "externalId", "value": ""}},
		})
	}
	if rec := clearExternalID(ids[0]); rec.Code != http.StatusOK {
		t.Fatalf("clear the first Marketing's externalId: status %d body %s", rec.Code, rec.Body)
	}
	if rec := clearExternalID(ids[1]); !isUniqueness(rec) {
		t.Errorf("clear the second Marketing's externalId: status %d body %s, want 409 uniqueness", rec.Code, rec.Body)
	}
}

// TestSCIMGroupOrganizationIsolation proves one organization can never read or mutate
// another organization's group via the SCIM surface.
func TestSCIMGroupOrganizationIsolation(t *testing.T) {
	ctx := dbtest.Context(t)
	a := newSCIMFixture(t, ctx)
	b := newSCIMFixture(t, ctx)

	rec := a.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": "OrganizationA-Only",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create in A: status %d", rec.Code)
	}
	gid, _ := decodeBody(t, rec)["id"].(string)

	// Organization B must not see it via get, patch, or delete.
	if rec := b.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B get A's group: status %d, want 404", rec.Code)
	}
	if rec := b.do(t, http.MethodDelete, "/scim/v2/Groups/"+gid, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B delete A's group: status %d, want 404", rec.Code)
	}
	// B's list must be empty (A's group not leaked).
	rec = b.do(t, http.MethodGet, "/scim/v2/Groups", nil)
	if total, _ := decodeBody(t, rec)["totalResults"].(float64); total != 0 {
		t.Fatalf("B list leaked A's group: totalResults = %v", decodeBody(t, rec)["totalResults"])
	}
	// A still sees it.
	if rec := a.do(t, http.MethodGet, "/scim/v2/Groups/"+gid, nil); rec.Code != http.StatusOK {
		t.Fatalf("A get its own group: status %d", rec.Code)
	}
}

// urlFilter builds the `displayName eq "x"` filter query value, URL-escaped.
func urlFilter(name string) string {
	return strings.ReplaceAll(`displayName+eq+%22`+name+`%22`, " ", "+")
}

// TestSCIMManagesOnlyItsOwnGroups checks that a directory can neither see
// nor change a group an administrator made, so it can't put anyone in one
// that carries roles, and that its changes to its own groups are audited
// member by member.
func TestSCIMManagesOnlyItsOwnGroups(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSCIMFixture(t, ctx)
	member := f.seedUser(t, ctx, dbtest.Unique("member")+"@example.test")
	var admins uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Admins') RETURNING id`, f.organizationID).Scan(&admins); err != nil {
		t.Fatal(err)
	}
	addMember := map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]string{{"value": member.String()}}}},
	}
	path := "/scim/v2/Groups/" + admins.String()
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"read":    f.do(t, http.MethodGet, path, nil),
		"patch":   f.do(t, http.MethodPatch, path, addMember),
		"replace": f.do(t, http.MethodPut, path, map[string]any{"schemas": []string{schemaGroup}, "displayName": "Admins", "members": []map[string]string{{"value": member.String()}}}),
		"delete":  f.do(t, http.MethodDelete, path, nil),
	} {
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s an administrator's group: %d %s, want 404", name, rec.Code, rec.Body.String())
		}
	}
	if rec := f.do(t, http.MethodGet, "/scim/v2/Groups?filter="+url.QueryEscape(`displayName eq "Admins"`), nil); decodeBody(t, rec)["totalResults"] != float64(0) {
		t.Errorf("listing found the administrator's group: %s", rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE group_id = $1`, admins); n != 0 || dbtest.Count(t, `SELECT count(*) FROM organization.groups WHERE id = $1`, admins) != 1 {
		t.Error("the directory changed an administrator's group")
	}

	rec := f.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{"schemas": []string{schemaGroup}, "displayName": "Engineering", "externalId": "eng"})
	id, _ := decodeBody(t, rec)["id"].(string)
	if rec.Code != http.StatusCreated || id == "" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, http.MethodPatch, "/scim/v2/Groups/"+id, addMember); rec.Code != http.StatusOK {
		t.Fatalf("add a member: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(t, http.MethodDelete, "/scim/v2/Groups/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	for _, action := range []string{"group.created", "group.member_added", "group.member_removed", "group.deleted"} {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE resource_id = $1 AND action = $2 AND actor_type = 'scim'`, uuid.MustParse(id), action); n != 1 {
			t.Errorf("%d %s records, want 1", n, action)
		}
	}
}

// seatPlan is a plan of n seats.
type seatPlan int

func (n seatPlan) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }

// TestDirectoryGroupMembershipTakesSeats checks that a directory adding someone
// holding no role to a group that carries one takes a seat, refused in the
// SCIM error format once the plan's seats are taken, by a PATCH and a PUT
// alike, and that the refused member isn't added.
func TestDirectoryGroupMembershipTakesSeats(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	plan := seatPlan(1)
	seats, err := invite.NewSeats(pool, &plan)
	if err != nil {
		t.Fatal(err)
	}
	f := newSCIMFixture(t, ctx, func(d *Deps) { d.Seats = seats })
	dbtest.User(t, f.organizationID, f.organizationID) // holds the one seat
	member := f.seedUser(t, ctx, dbtest.Unique("member")+"@acme.test")

	rec := f.do(t, http.MethodPost, "/scim/v2/Groups", map[string]any{"schemas": []string{schemaGroup}, "displayName": "Support"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	gid, _ := decodeBody(t, rec)["id"].(string)
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`,
		f.organizationID, gid, dbtest.Role(t, f.organizationID)); err != nil {
		t.Fatal(err)
	}

	for name, req := range map[string]struct {
		method string
		body   map[string]any
	}{
		"PATCH add": {http.MethodPatch, map[string]any{
			"schemas":    []string{schemaPatchOp},
			"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": member.String()}}}},
		}},
		"PUT": {http.MethodPut, map[string]any{
			"schemas": []string{schemaGroup}, "displayName": "Support", "members": []map[string]any{{"value": member.String()}},
		}},
	} {
		rec := f.do(t, req.method, "/scim/v2/Groups/"+gid, req.body)
		body := decodeBody(t, rec)
		if rec.Code != http.StatusForbidden || body["schemas"] == nil || body["status"] != "403" {
			t.Errorf("%s with no seat left: status %d %s, want a SCIM 403", name, rec.Code, rec.Body.String())
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE group_id = $1`, gid); n != 0 {
		t.Errorf("%d members added past the seat limit, want none", n)
	}

	plan = -1 // a plan without a seat limit
	rec = f.do(t, http.MethodPatch, "/scim/v2/Groups/"+gid, map[string]any{
		"schemas":    []string{schemaPatchOp},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": member.String()}}}},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("PATCH add on a plan without a seat limit: status %d %s", rec.Code, rec.Body.String())
	}
}
