//go:build integration

package rebac

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestTuplesGrantRelations checks that tuples written over HTTP are listed by
// object and by subject, grant their relation directly or through nested
// groups up to the depth limit and around cycles, and show in the graph; that a
// role grant counts without a tuple; that changes are audited and a deleted
// tuple stops granting; and that malformed requests are refused.
func TestTuplesGrantRelations(t *testing.T) {
	ctx := dbtest.Context(t)
	rh := newHandler(t)
	svc := rh.Service
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	alice, erin, stranger := dbtest.User(t, organization), dbtest.User(t, organization), dbtest.User(t, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), rh.Mount)
	base := "/organizations/" + organization.String() + "/relation-tuples"
	aliceSubject, erinSubject := "user:"+alice.ID.String(), "user:"+erin.ID.String()
	audited := func(action string, id uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3 AND actor_user_id = $4`, organization, action, id, admin.ID)
	}
	announced := func(eventType string, id uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = $1 AND aggregate_id = $2`, eventType, id)
	}

	direct := writeTuple(t, h, organization, "document:readme", "viewer", aliceSubject)
	if audited("rebac.tuple_written", direct.ID) != 1 || announced("rebac.tuple_written", direct.ID) != 1 {
		t.Error("the write was not audited and announced as the administrator's")
	}
	if again := writeTuple(t, h, organization, "document:readme", "viewer", aliceSubject); again.ID != direct.ID {
		t.Errorf("writing a tuple twice: ids %s and %s, want one", direct.ID, again.ID)
	}
	writeTuple(t, h, organization, "document:readme", "viewer", "group:eng#member")
	writeTuple(t, h, organization, "group:eng", "member", "group:core#member")
	writeTuple(t, h, organization, "group:core", "member", erinSubject)

	subjects := func(query string) []string {
		t.Helper()
		var list struct {
			Items []Tuple `json:"items"`
		}
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"?"+query, nil), &list)
		var out []string
		for _, tu := range list.Items {
			out = append(out, tu.Object+"#"+tu.Relation+"@"+tu.Subject)
		}
		return out
	}
	if got, want := subjects("object=document:readme"), []string{"document:readme#viewer@group:eng#member", "document:readme#viewer@" + aliceSubject}; !slices.Equal(got, want) {
		t.Errorf("tuples on the document: %q, want %q", got, want)
	}
	if got, want := subjects("subject=group:core"), []string{"group:eng#member@group:core#member"}; !slices.Equal(got, want) {
		t.Errorf("tuples naming group:core: %q, want %q", got, want)
	}

	for _, tc := range []struct {
		name, relation string
		user           uuid.UUID
		want           bool
	}{
		{"a direct viewer", "viewer", alice.ID, true},
		{"a viewer through nested groups", "viewer", erin.ID, true},
		{"a viewer asked about another relation", "editor", alice.ID, false},
		{"a stranger", "viewer", stranger.ID, false},
	} {
		if got := ask(t, h, organization, "document:readme", tc.relation, tc.user.String()).Allowed; got != tc.want {
			t.Errorf("check for %s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := ask(t, h, organization, "document:readme", "viewer", erin.ID.String()); got.DecidedBy["model"] != decide.ModelReBAC ||
		len(got.Path) != 3 || got.Path[0].Subject != "group:eng#member" || got.Path[2].Subject != erinSubject {
		t.Errorf("explained check through nested groups: %+v; want decided by the tuples via eng and core", got)
	}
	reader := dbtest.User(t, organization)
	dbtest.Assign(t, reader.ID, organization, dbtest.Role(t, organization, "document:viewer"))
	if got := ask(t, h, organization, "document:readme", "viewer", reader.ID.String()); !got.Allowed || got.DecidedBy["model"] != decide.ModelRBAC {
		t.Errorf("check for a role holding document:viewer: %+v, want allowed by the role", got)
	}

	// group:g0 ⊇ group:g1 ⊇ … ⊇ group:g26, whose one member is "deep".
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}
	for i := range maxDepth + 1 {
		if _, err := svc.Write(ctx, organization, fmt.Sprintf("group:g%d", i), "member", fmt.Sprintf("group:g%d#member", i+1), actor); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Write(ctx, organization, fmt.Sprintf("group:g%d", maxDepth+1), "member", "user:deep", actor); err != nil {
		t.Fatal(err)
	}
	for start, want := range map[int]bool{1: true, 0: false} {
		if got, err := svc.Check(ctx, organization, fmt.Sprintf("group:g%d", start), "member", "deep"); err != nil || got != want {
			t.Errorf("check for a member %d nested groups down: %v, %v; want %v", maxDepth+1-start, got, err, want)
		}
	}
	writeTuple(t, h, organization, "group:a", "member", "group:b#member")
	writeTuple(t, h, organization, "group:b", "member", "group:a#member")
	if ask(t, h, organization, "group:a", "member", stranger.ID.String()).Allowed {
		t.Error("check around a cycle of groups: true, want false")
	}

	graph := func(depth string) Graph {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, base+"/graph?object=document:readme&relation=viewer&depth="+depth, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("graph: %d %s", rec.Code, rec.Body.String())
		}
		var g Graph
		dbtest.Decode(t, rec, &g)
		return g
	}
	reaches := func(g Graph, id string) bool {
		return slices.ContainsFunc(g.Nodes, func(n GraphNode) bool { return n.ID == id })
	}
	full := graph("")
	if !reaches(full, aliceSubject) || !reaches(full, erinSubject) ||
		!slices.Contains(full.Edges, GraphEdge{From: "document:readme", To: "group:eng", Relation: "viewer → member"}) {
		t.Errorf("graph %+v; want both viewers, and the document reached through group:eng", full)
	}
	if reaches(graph("1"), erinSubject) {
		t.Error("graph to depth 1 reached a viewer two groups down")
	}

	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+direct.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if ask(t, h, organization, "document:readme", "viewer", alice.ID.String()).Allowed {
		t.Error("check after the tuple was deleted: true, want false")
	}
	if audited("rebac.tuple_deleted", direct.ID) != 1 || announced("rebac.tuple_deleted", direct.ID) != 1 {
		t.Error("the delete was not audited and announced as the administrator's")
	}
	var removed map[string]any
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT metadata FROM audit.events WHERE organization_id = $1 AND action = 'rebac.tuple_deleted' AND resource_id = $2`, organization, direct.ID).Scan(&removed); err != nil {
		t.Fatal(err)
	}
	if removed["object"] != direct.Object || removed["relation"] != direct.Relation || removed["subject"] != direct.Subject {
		t.Errorf("the deletion's audit metadata: %v, want the tuple %s#%s@%s", removed, direct.Object, direct.Relation, direct.Subject)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+direct.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("deleting the tuple again: %d, want 404", rec.Code)
	}

	for _, tc := range []struct {
		method, path string
		body         any
		status       int
		code         string
	}{
		{http.MethodPost, base, map[string]string{"object": "readme", "relation": "viewer", "subject": aliceSubject}, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodPost, base, map[string]string{"object": "document:readme", "relation": "viewer", "subject": "group:eng#"}, http.StatusUnprocessableEntity, CodeSubjectInvalid},
		{http.MethodPost, base, map[string]string{"object": "document:readme", "relation": " ", "subject": aliceSubject}, http.StatusUnprocessableEntity, CodeRelationRequired},
		{http.MethodGet, base, nil, http.StatusBadRequest, CodeObjectOrSubjectRequired},
		{http.MethodGet, base + "?object=document:readme&subject=" + aliceSubject, nil, http.StatusBadRequest, CodeObjectSubjectExclusive},
		{http.MethodGet, base + "?object=readme", nil, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodGet, base + "?subject=alice", nil, http.StatusUnprocessableEntity, CodeSubjectInvalid},
		{http.MethodPost, base + "/check", map[string]string{"object": "document:readme", "relation": "viewer"}, http.StatusUnprocessableEntity, CodeUserIDRelationRequired},
		{http.MethodPost, base + "/check", map[string]string{"object": "readme", "relation": "viewer", "user_id": alice.ID.String()}, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodGet, base + "/graph?object=document:readme", nil, http.StatusBadRequest, CodeObjectRelationRequired},
		{http.MethodGet, base + "/graph?object=readme&relation=viewer", nil, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodDelete, base + "/not-a-uuid", nil, http.StatusBadRequest, errs.CodeBadRequest},
	} {
		if rec := dbtest.Do(t, h, tc.method, tc.path, tc.body); rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s %s: %d %s, want %d %s", tc.method, tc.path, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}

	t.Run("a shorter path to a group the depth limit cut off", func(t *testing.T) {
		writeTuple(t, h, organization, "document:deep", "viewer", "group:g0#member")
		writeTuple(t, h, organization, "document:deep", "viewer", "group:g24#member")
		if ok, err := svc.Check(ctx, organization, "document:deep", "viewer", "deep"); err != nil || !ok {
			t.Errorf("check for a viewer three groups down by the short path: %v, %v; want true", ok, err)
		}
	})
}
