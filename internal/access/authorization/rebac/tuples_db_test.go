//go:build integration

package rebac

import (
	"errors"
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestTuplesStayInTheirOrganization checks that another organization can't
// list, check against, write to or delete an organization's tuples, over HTTP
// or through the service, and that its own tuples under the same names grant
// nothing in the first.
func TestTuplesStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	rh := newHandler(t)
	svc := rh.Service
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin, otherAdmin := dbtest.User(t, organization, organization), dbtest.User(t, other, other)
	alice, mallory := dbtest.User(t, organization), dbtest.User(t, other)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), rh.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), rh.Mount)
	base, otherBase := "/organizations/"+organization.String()+"/relation-tuples", "/organizations/"+other.String()+"/relation-tuples"

	shared := writeTuple(t, h, organization, "document:readme", "viewer", "group:eng#member")
	writeTuple(t, h, organization, "group:eng", "member", "user:"+alice.ID.String())
	writeTuple(t, asOther, other, "group:eng", "member", "user:"+mallory.ID.String())

	if ask(t, h, organization, "document:readme", "viewer", mallory.ID.String()).Allowed {
		t.Error("check through another organization's group of the same name: true, want false")
	}
	if ask(t, asOther, other, "document:readme", "viewer", alice.ID.String()).Allowed {
		t.Error("check across organizations: true, want false")
	}
	if ok, err := svc.Check(ctx, other, "document:readme", "viewer", alice.ID.String()); err != nil || ok {
		t.Errorf("service check across organizations: %v, %v; want false", ok, err)
	}
	var list struct {
		Items []Tuple `json:"items"`
	}
	for _, query := range []string{"?object=document:readme", "?subject=user:" + alice.ID.String()} {
		dbtest.Decode(t, dbtest.Do(t, asOther, http.MethodGet, otherBase+query, nil), &list)
		if len(list.Items) != 0 {
			t.Errorf("another organization listing %s: %+v, want none", query, list.Items)
		}
	}
	if got, err := svc.List(ctx, other, "document:readme"); err != nil || len(got) != 0 {
		t.Errorf("service list across organizations: %+v, %v; want none", got, err)
	}
	var g Graph
	dbtest.Decode(t, dbtest.Do(t, asOther, http.MethodGet, otherBase+"/graph?object=document:readme&relation=viewer", nil), &g)
	if len(g.Edges) != 0 {
		t.Errorf("another organization's graph of the document: %+v, want no edges", g.Edges)
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
			t.Errorf("another organization %s %s: %d, want 403", tc.method, tc.path, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodDelete, otherBase+"/"+shared.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization deleting the tuple: %d, want 404", rec.Code)
	}
	if err := svc.Delete(ctx, shared.ID, other, audit.Actor{Type: "system"}); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("service delete across organizations: %v, want %v", err, errs.ErrNotFound)
	}
	if !ask(t, h, organization, "document:readme", "viewer", alice.ID.String()).Allowed {
		t.Error("check after another organization tried to delete the tuple: false, want true")
	}
}
