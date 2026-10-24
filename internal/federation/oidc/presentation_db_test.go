//go:build integration

package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestApplicationLogoAndHomePage checks that an admin sets, changes and clears
// an application's logo and home page, that only https addresses are taken,
// and that the hosted sign-in page's context returns what was registered and
// leaves out what wasn't, whatever the request carries.
func TestApplicationLogoAndHomePage(t *testing.T) {
	p := newProvider(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: p.svc}).Mount)
	clients := "/tenants/" + tenant.String() + "/oidc/clients"
	const logo, home = "https://cdn.acme.example.test/notes.svg", "https://acme.example.test"

	var created struct {
		Client Client `json:"client"`
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, clients, map[string]any{
		"name": "Acme Notes", "redirect_uris": []string{testRedirect}, "logo_uri": logo, "client_uri": home,
	})
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.Client.LogoURI != logo || created.Client.ClientURI != home {
		t.Fatalf("create: %d %s, want the logo and home page kept", rec.Code, rec.Body.String())
	}
	context := func(clientID string) map[string]any {
		t.Helper()
		var out map[string]any
		rec := browse(t, p.public, http.MethodGet, "/oauth/login-context?client_id="+clientID+"&logo_uri=https://evil.example.test/x.png", nil, nil)
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("login context: %d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	if got := context(created.Client.ClientID); got["logo_uri"] != logo || got["client_uri"] != home {
		t.Errorf("login context: %v, want the registered logo and home page", got)
	}

	path := clients + "/" + created.Client.ID.String()
	for _, body := range []map[string]any{
		{"logo_uri": "http://cdn.acme.example.test/notes.svg"},
		{"logo_uri": "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="},
		{"client_uri": "https://user:pass@acme.example.test"},
		{"client_uri": "https://acme.example.test/#top"},
		{"client_uri": "/relative"},
		{"logo_uri": "https://acme.example.test/" + strings.Repeat("a", 2048)},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, body); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errs.CodeBadRequest) {
			t.Errorf("PATCH %v: %d %s, want 400", body, rec.Code, rec.Body.String())
		}
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, clients, map[string]any{
		"name": "Bad", "redirect_uris": []string{testRedirect}, "logo_uri": "http://cdn.acme.example.test/x.svg",
	}); rec.Code != http.StatusBadRequest {
		t.Errorf("create with an http logo: %d, want 400", rec.Code)
	}

	var patched Client
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"name": "Acme Notes 2"}), &patched)
	if patched.LogoURI != logo || patched.ClientURI != home {
		t.Errorf("an edit that leaves them out: %+v, want them kept", patched)
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"logo_uri": "", "client_uri": "https://notes.acme.example.test"}), &patched)
	if patched.LogoURI != "" || patched.ClientURI != "https://notes.acme.example.test" {
		t.Errorf("clear the logo, move the home page: %+v", patched)
	}
	got := context(created.Client.ClientID)
	if _, ok := got["logo_uri"]; ok || got["client_uri"] != "https://notes.acme.example.test" {
		t.Errorf("login context after the edit: %v, want no logo_uri and the new home page", got)
	}
}
