//go:build integration

package scim

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// planGate includes SCIM in the plans of the tenants it holds.
type planGate map[uuid.UUID]bool

func (g planGate) FeatureAllowed(_ context.Context, tenantID uuid.UUID, _ string) (bool, error) {
	return g[tenantID], nil
}

// TestLapsedPlanStopsSCIM checks that a SCIM token issued while the plan
// included SCIM provisions nothing once the plan has lapsed.
func TestLapsedPlanStopsSCIM(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSCIMFixture(t, ctx)
	plans := planGate{f.tenantID: true}
	f.svc.SetPlanGate(plans)
	if rec := f.do(t, http.MethodGet, "/scim/v2/Users", nil); rec.Code != http.StatusOK {
		t.Fatalf("SCIM on a plan with it: status %d", rec.Code)
	}

	delete(plans, f.tenantID) // the plan lapses
	rec := f.do(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": dbtest.Unique("new") + "@example.test",
	})
	if rec.Code != http.StatusForbidden || decodeBody(t, rec)["schemas"] == nil {
		t.Errorf("SCIM after the plan lapsed: status %d %s, want a SCIM 403", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE tenant_id = $1`, f.tenantID); n != 0 {
		t.Errorf("%d users provisioned after the plan lapsed, want none", n)
	}
}

// TestSCIMUserReadsStayInTheirTenant checks that one tenant's SCIM token can
// neither find, read nor delete another tenant's user.
func TestSCIMUserReadsStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	a := newSCIMFixture(t, ctx)
	b := newSCIMFixture(t, ctx)
	email := dbtest.Unique("victim") + "@a.example.test"
	victim := a.seedUser(t, ctx, email)

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/scim/v2/Users/" + victim.String(), http.StatusNotFound},
		{http.MethodDelete, "/scim/v2/Users/" + victim.String(), http.StatusNotFound},
	} {
		if rec := b.do(t, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("B %s %s: status %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
	for _, path := range []string{"/scim/v2/Users", "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "`+email+`"`)} {
		if total := decodeBody(t, b.do(t, http.MethodGet, path, nil))["totalResults"]; total != float64(0) {
			t.Errorf("B GET %s: totalResults %v, want 0", path, total)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND deleted_at IS NULL`, victim); n != 1 {
		t.Error("B's SCIM token deleted A's user")
	}
	if rec := a.do(t, http.MethodGet, "/scim/v2/Users/"+victim.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("A reads its own user: status %d", rec.Code)
	}
}
