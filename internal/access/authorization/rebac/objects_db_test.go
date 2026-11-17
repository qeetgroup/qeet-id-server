//go:build integration

package rebac

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestObjectsAndTypesListAndPeopleAreNamed checks that the organization's object
// types and a type's objects are listed, the objects a page at a time, and
// that people in tuples and the graph are named when they belong to the
// organization, and not otherwise.
func TestObjectsAndTypesListAndPeopleAreNamed(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	member, stranger := dbtest.User(t, organization, organization), dbtest.User(t, other, other)
	system := audit.Actor{Type: "system"}
	for _, tu := range [][3]string{
		{"document:a", "viewer", "user:" + member.ID.String()},
		{"document:a", "viewer", "user:" + stranger.ID.String()},
		{"document:b", "editor", "user:" + member.ID.String()},
		{"document:c", "viewer", "group:eng#member"},
		{"group:eng", "member", "user:" + member.ID.String()},
	} {
		if _, err := svc.Write(ctx, organization, tu[0], tu[1], tu[2], system); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Write(ctx, other, "folder:x", "viewer", "user:"+stranger.ID.String(), system); err != nil {
		t.Fatal(err)
	}

	types, err := svc.ObjectTypes(ctx, organization)
	if err != nil || len(types) != 2 || types[0] != (ObjectType{Type: "document", Objects: 3, Tuples: 4}) || types[1] != (ObjectType{Type: "group", Objects: 1, Tuples: 1}) {
		t.Errorf("object types: %+v, %v; want document (3 objects, 4 tuples) and group", types, err)
	}
	page, err := svc.Objects(ctx, organization, "document", 2, "")
	if err != nil || page.Total != 3 || len(page.Items) != 2 || page.Items[0].Object != "document:a" || page.Items[0].Tuples != 2 || page.NextCursor == "" {
		t.Fatalf("first page of documents: %+v, %v", page, err)
	}
	rest, err := svc.Objects(ctx, organization, "document", 2, page.NextCursor)
	if err != nil || len(rest.Items) != 1 || rest.Items[0].ID != "c" || rest.NextCursor != "" {
		t.Errorf("second page of documents: %+v, %v; want document:c alone", rest, err)
	}
	if none, err := svc.Objects(ctx, other, "document", 0, ""); err != nil || none.Total != 0 {
		t.Errorf("another tenant's documents: %+v, %v; want none", none, err)
	}

	tuples, err := svc.List(ctx, organization, "document:a")
	if err != nil || len(tuples) != 2 {
		t.Fatalf("document:a's tuples: %+v, %v", tuples, err)
	}
	for _, tu := range tuples {
		want := ""
		if tu.Subject == "user:"+member.ID.String() {
			want = member.Email
		}
		if tu.SubjectName != want {
			t.Errorf("tuple %s named %q, want %q", tu.Subject, tu.SubjectName, want)
		}
	}
	graph, err := svc.Expand(ctx, organization, "document:c", "viewer", 0)
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, n := range graph.Nodes {
		named = named || (n.ID == "user:"+member.ID.String() && n.Name == member.Email)
	}
	if !named {
		t.Errorf("graph nodes %+v; want the member named", graph.Nodes)
	}
}
