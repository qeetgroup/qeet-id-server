//go:build integration

package rebac

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/abac"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/decide"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newHandler returns the relationship routes' handler, deciding checks across
// roles, relationships and attribute policies as the server does.
func newHandler(t *testing.T) *Handler {
	t.Helper()
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	return &Handler{Service: svc, Decider: decide.New(rbac.NewRepository(pool), svc, abac.NewService(pool))}
}

// writeTuple stores the tuple object#relation@subject through h's write route.
func writeTuple(t *testing.T, h http.Handler, tenant uuid.UUID, object, relation, subject string) Tuple {
	t.Helper()
	rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+tenant.String()+"/relation-tuples",
		map[string]string{"object": object, "relation": relation, "subject": subject})
	if rec.Code != http.StatusCreated {
		t.Fatalf("write %s#%s@%s: %d %s", object, relation, subject, rec.Code, rec.Body.String())
	}
	var out Tuple
	dbtest.Decode(t, rec, &out)
	return out
}

// checkResult is the check route's answer when asked to explain itself.
type checkResult struct {
	Allowed   bool           `json:"allowed"`
	DecidedBy map[string]any `json:"decided_by"`
	Path      []ExplainStep  `json:"path"`
}

// ask asks h's check route, with an explanation, whether user holds relation
// on object.
func ask(t *testing.T, h http.Handler, tenant uuid.UUID, object, relation, user string) checkResult {
	t.Helper()
	rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+tenant.String()+"/relation-tuples/check?explain=true",
		map[string]string{"object": object, "relation": relation, "user_id": user})
	if rec.Code != http.StatusOK {
		t.Fatalf("check %s#%s for %s: %d %s", object, relation, user, rec.Code, rec.Body.String())
	}
	var out checkResult
	dbtest.Decode(t, rec, &out)
	return out
}

// TestTuplesGrantRelations checks that tuples written over HTTP are listed by
// object and by subject, grant their relation directly or through nested
// groups up to the depth limit and around cycles, and show in the graph; that a
// role grant counts without a tuple; that changes are audited and a deleted
// tuple stops granting; and that malformed requests are refused.
func TestTuplesGrantRelations(t *testing.T) {
	ctx := dbtest.Context(t)
	rh := newHandler(t)
	svc := rh.Service
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	alice, erin, stranger := dbtest.User(t, tenant), dbtest.User(t, tenant), dbtest.User(t, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), rh.Mount)
	base := "/tenants/" + tenant.String() + "/relation-tuples"
	aliceSubject, erinSubject := "user:"+alice.ID.String(), "user:"+erin.ID.String()
	audited := func(action string, id uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2 AND resource_id = $3 AND actor_user_id = $4`, tenant, action, id, admin.ID)
	}
	announced := func(eventType string, id uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE event_type = $1 AND aggregate_id = $2`, eventType, id)
	}

	direct := writeTuple(t, h, tenant, "document:readme", "viewer", aliceSubject)
	if audited("rebac.tuple_written", direct.ID) != 1 || announced("rebac.tuple_written", direct.ID) != 1 {
		t.Error("the write was not audited and announced as the administrator's")
	}
	if again := writeTuple(t, h, tenant, "document:readme", "viewer", aliceSubject); again.ID != direct.ID {
		t.Errorf("writing a tuple twice: ids %s and %s, want one", direct.ID, again.ID)
	}
	writeTuple(t, h, tenant, "document:readme", "viewer", "group:eng#member")
	writeTuple(t, h, tenant, "group:eng", "member", "group:core#member")
	writeTuple(t, h, tenant, "group:core", "member", erinSubject)

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
		if got := ask(t, h, tenant, "document:readme", tc.relation, tc.user.String()).Allowed; got != tc.want {
			t.Errorf("check for %s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := ask(t, h, tenant, "document:readme", "viewer", erin.ID.String()); got.DecidedBy["model"] != decide.ModelReBAC ||
		len(got.Path) != 3 || got.Path[0].Subject != "group:eng#member" || got.Path[2].Subject != erinSubject {
		t.Errorf("explained check through nested groups: %+v; want decided by the tuples via eng and core", got)
	}
	reader := dbtest.User(t, tenant)
	dbtest.Assign(t, reader.ID, tenant, dbtest.Role(t, tenant, "document:viewer"))
	if got := ask(t, h, tenant, "document:readme", "viewer", reader.ID.String()); !got.Allowed || got.DecidedBy["model"] != decide.ModelRBAC {
		t.Errorf("check for a role holding document:viewer: %+v, want allowed by the role", got)
	}

	// group:g0 ⊇ group:g1 ⊇ … ⊇ group:g26, whose one member is "deep".
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}
	for i := range maxDepth + 1 {
		if _, err := svc.Write(ctx, tenant, fmt.Sprintf("group:g%d", i), "member", fmt.Sprintf("group:g%d#member", i+1), actor); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Write(ctx, tenant, fmt.Sprintf("group:g%d", maxDepth+1), "member", "user:deep", actor); err != nil {
		t.Fatal(err)
	}
	for start, want := range map[int]bool{1: true, 0: false} {
		if got, err := svc.Check(ctx, tenant, fmt.Sprintf("group:g%d", start), "member", "deep"); err != nil || got != want {
			t.Errorf("check for a member %d nested groups down: %v, %v; want %v", maxDepth+1-start, got, err, want)
		}
	}
	writeTuple(t, h, tenant, "group:a", "member", "group:b#member")
	writeTuple(t, h, tenant, "group:b", "member", "group:a#member")
	if ask(t, h, tenant, "group:a", "member", stranger.ID.String()).Allowed {
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
	if ask(t, h, tenant, "document:readme", "viewer", alice.ID.String()).Allowed {
		t.Error("check after the tuple was deleted: true, want false")
	}
	if audited("rebac.tuple_deleted", direct.ID) != 1 || announced("rebac.tuple_deleted", direct.ID) != 1 {
		t.Error("the delete was not audited and announced as the administrator's")
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
		{http.MethodPost, base, map[string]string{"object": "document:readme", "relation": "viewer", "subject": "group:eng#"}, http.StatusUnprocessableEntity, errs.CodeReBACSubjectInvalid},
		{http.MethodPost, base, map[string]string{"object": "document:readme", "relation": " ", "subject": aliceSubject}, http.StatusUnprocessableEntity, errs.CodeReBACRelationRequired},
		{http.MethodGet, base, nil, http.StatusBadRequest, errs.CodeReBACObjectOrSubjectRequired},
		{http.MethodGet, base + "?object=document:readme&subject=" + aliceSubject, nil, http.StatusBadRequest, errs.CodeReBACObjectSubjectExclusive},
		{http.MethodGet, base + "?object=readme", nil, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodGet, base + "?subject=alice", nil, http.StatusUnprocessableEntity, errs.CodeReBACSubjectInvalid},
		{http.MethodPost, base + "/check", map[string]string{"object": "document:readme", "relation": "viewer"}, http.StatusUnprocessableEntity, errs.CodeReBACUserIDRelationRequired},
		{http.MethodPost, base + "/check", map[string]string{"object": "readme", "relation": "viewer", "user_id": alice.ID.String()}, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodGet, base + "/graph?object=document:readme", nil, http.StatusBadRequest, errs.CodeReBACObjectRelationRequired},
		{http.MethodGet, base + "/graph?object=readme&relation=viewer", nil, http.StatusUnprocessableEntity, errs.CodeReBACObjectInvalid},
		{http.MethodDelete, base + "/not-a-uuid", nil, http.StatusBadRequest, errs.CodeBadRequest},
	} {
		if rec := dbtest.Do(t, h, tc.method, tc.path, tc.body); rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s %s: %d %s, want %d %s", tc.method, tc.path, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}

	t.Run("a shorter path to a group the depth limit cut off", func(t *testing.T) {
		writeTuple(t, h, tenant, "document:deep", "viewer", "group:g0#member")
		writeTuple(t, h, tenant, "document:deep", "viewer", "group:g24#member")
		if ok, err := svc.Check(ctx, tenant, "document:deep", "viewer", "deep"); err != nil || !ok {
			t.Errorf("check for a viewer three groups down by the short path: %v, %v; want true", ok, err)
		}
	})
}

// TestTuplesStayInTheirOrganisation checks that another organisation can't
// list, check against, write to or delete an organisation's tuples, over HTTP
// or through the service, and that its own tuples under the same names grant
// nothing in the first.
func TestTuplesStayInTheirOrganisation(t *testing.T) {
	ctx := dbtest.Context(t)
	rh := newHandler(t)
	svc := rh.Service
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin, otherAdmin := dbtest.User(t, tenant, tenant), dbtest.User(t, other, other)
	alice, mallory := dbtest.User(t, tenant), dbtest.User(t, other)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), rh.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), rh.Mount)
	base, otherBase := "/tenants/"+tenant.String()+"/relation-tuples", "/tenants/"+other.String()+"/relation-tuples"

	shared := writeTuple(t, h, tenant, "document:readme", "viewer", "group:eng#member")
	writeTuple(t, h, tenant, "group:eng", "member", "user:"+alice.ID.String())
	writeTuple(t, asOther, other, "group:eng", "member", "user:"+mallory.ID.String())

	if ask(t, h, tenant, "document:readme", "viewer", mallory.ID.String()).Allowed {
		t.Error("check through another organisation's group of the same name: true, want false")
	}
	if ask(t, asOther, other, "document:readme", "viewer", alice.ID.String()).Allowed {
		t.Error("check across organisations: true, want false")
	}
	if ok, err := svc.Check(ctx, other, "document:readme", "viewer", alice.ID.String()); err != nil || ok {
		t.Errorf("service check across organisations: %v, %v; want false", ok, err)
	}
	var list struct {
		Items []Tuple `json:"items"`
	}
	for _, query := range []string{"?object=document:readme", "?subject=user:" + alice.ID.String()} {
		dbtest.Decode(t, dbtest.Do(t, asOther, http.MethodGet, otherBase+query, nil), &list)
		if len(list.Items) != 0 {
			t.Errorf("another organisation listing %s: %+v, want none", query, list.Items)
		}
	}
	if got, err := svc.List(ctx, other, "document:readme"); err != nil || len(got) != 0 {
		t.Errorf("service list across organisations: %+v, %v; want none", got, err)
	}
	var g Graph
	dbtest.Decode(t, dbtest.Do(t, asOther, http.MethodGet, otherBase+"/graph?object=document:readme&relation=viewer", nil), &g)
	if len(g.Edges) != 0 {
		t.Errorf("another organisation's graph of the document: %+v, want no edges", g.Edges)
	}

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, base + "?object=document:readme", nil},
		{http.MethodPost, base, map[string]string{"object": "document:readme", "relation": "viewer", "subject": "user:" + mallory.ID.String()}},
		{http.MethodPost, base + "/check", map[string]string{"object": "document:readme", "relation": "viewer", "user_id": alice.ID.String()}},
		{http.MethodGet, base + "/graph?object=document:readme&relation=viewer", nil},
		{http.MethodDelete, base + "/" + shared.ID.String(), nil},
	} {
		if rec := dbtest.Do(t, asOther, tc.method, tc.path, tc.body); rec.Code != http.StatusForbidden {
			t.Errorf("another organisation %s %s: %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase+"/"+shared.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation deleting the tuple: %d, want 404", rec.Code)
	}
	if err := svc.Delete(ctx, shared.ID, other, audit.Actor{Type: "system"}); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("service delete across organisations: %v, want %v", err, errs.ErrNotFound)
	}
	if !ask(t, h, tenant, "document:readme", "viewer", alice.ID.String()).Allowed {
		t.Error("check after another organisation tried to delete the tuple: false, want true")
	}
}
