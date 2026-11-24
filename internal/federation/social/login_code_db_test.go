//go:build integration

package social

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestSocialCodeOfAProviderTurnedOffDoesNotExchange checks that a login code
// issued just before its provider was switched off or deleted signs nobody in.
func TestSocialCodeOfAProviderTurnedOffDoesNotExchange(t *testing.T) {
	f := newSocialFixture(t)
	organization := dbtest.Organization(t)
	asAdmin := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), f.mount)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	person := verified(t, member)
	for _, tc := range []struct{ provider, change, want string }{
		{"okta", `UPDATE organization.social_providers SET enabled = false WHERE organization_id = $1 AND provider = $2`, ErrProviderNotConfigured.Code},
		{"keycloak", `DELETE FROM organization.social_providers WHERE organization_id = $1 AND provider = $2`, CodeLoginCodeInvalid},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/social/providers", map[string]string{
			"provider": tc.provider, "client_id": "qeet", "client_secret": "idp-client-secret",
			"discovery_url": f.idp.URL + "/.well-known/openid-configuration",
		}); rec.Code != http.StatusOK {
			t.Fatalf("add provider: %d %s", rec.Code, rec.Body.String())
		}
		_, q := redirectQuery(t, f.signIn(t, tc.provider, "/social/"+tc.provider+"/start?organization_id="+organization.String(), person))
		if q.Get("code") == "" {
			t.Fatalf("sign-in: %v, want a one-time code", q)
		}
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), tc.change, organization, tc.provider); err != nil {
			t.Fatal(err)
		}
		if rec := browse(t, f.public, http.MethodPost, "/social/exchange", nil, map[string]string{"code": q.Get("code")}); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s %s, then exchange its code: %d %.80s, want %s", tc.change, tc.provider, rec.Code, rec.Body.String(), tc.want)
		}
	}
}
