//go:build integration

package oidc

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestApplicationWebOrigins checks the origins a browser application may call
// the OAuth endpoints from: its redirect URIs' origins unless it sets its
// own, which are checked and stored in lower case, and its redirect URIs'
// again once it sets null; and that the CORS check allows exactly the
// origins some application allows.
func TestApplicationWebOrigins(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	clients := "/organizations/" + organization.String() + "/oidc/clients"
	spa := "https://" + dbtest.Unique("spa") + ".example.test"

	var created struct {
		Client Client `json:"client"`
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, clients, map[string]any{
		"name": "SPA", "type": "public", "redirect_uris": []string{spa + "/callback", "com.example.app:/callback"},
	})
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || !slices.Equal(created.Client.WebOrigins, []string{spa}) {
		t.Fatalf("create: %d %s; want its redirect URI's origin and no native scheme", rec.Code, rec.Body.String())
	}
	if !svc.AllowsWebOrigin(ctx, spa) || svc.AllowsWebOrigin(ctx, "https://other.example.test") {
		t.Error("the CORS check doesn't allow exactly the application's origin")
	}

	path := clients + "/" + created.Client.ID.String()
	other := "https://" + dbtest.Unique("app") + ".example.test"
	var got Client
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"web_origins": []string{strings.ToUpper(other), "http://localhost:5173"}})
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusOK || !slices.Equal(got.WebOrigins, []string{other, "http://localhost:5173"}) {
		t.Fatalf("set web origins: %d %s", rec.Code, rec.Body.String())
	}
	if !svc.AllowsWebOrigin(ctx, other) || svc.AllowsWebOrigin(ctx, spa) {
		t.Error("the CORS check didn't follow the origins the application set")
	}
	for _, bad := range []string{"*", "http://app.example.test", "https://app.example.test/path", "https://user@app.example.test", "app.example.test"} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"web_origins": []string{bad}}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), CodeWebOriginInvalid) {
			t.Errorf("web origin %q: %d %s, want 422 %s", bad, rec.Code, rec.Body.String(), CodeWebOriginInvalid)
		}
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"web_origins": nil})
	got = Client{}
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusOK || !slices.Equal(got.WebOrigins, []string{spa}) {
		t.Errorf("web origins back to the redirect URIs': %d %v", rec.Code, got.WebOrigins)
	}
	got = Client{}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, path, nil), &got)
	if !slices.Equal(got.WebOrigins, []string{spa}) {
		t.Errorf("read back: %v, want the redirect URI's origin", got.WebOrigins)
	}
}
