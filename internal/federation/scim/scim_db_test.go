//go:build integration

package scim

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

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
