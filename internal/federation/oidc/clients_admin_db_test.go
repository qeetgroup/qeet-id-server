//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestApplicationAdministration checks that a client is created in the path's
// organization whatever the body says, its secret shown once and retired by
// rotation, edits held to the registration rules, wrong secrets listed without
// the secret, and that deleting it stops it authenticating, each audited.
func TestApplicationAdministration(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	clients := "/organizations/" + organization.String() + "/oidc/clients"
	app := map[string]any{"organization_id": otherOrganization, "name": "Portal", "redirect_uris": []string{testRedirect}}

	rec := dbtest.Do(t, asAdmin, http.MethodPost, clients, app)
	var created struct {
		Client Client `json:"client"`
		Secret string `json:"client_secret"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.Client.OrganizationID != organization || created.Secret == "" {
		t.Fatalf("create: %d %s, want a client of the path's organization and its secret", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_clients WHERE id = $1 AND organization_id = $2 AND created_by = $3`, created.Client.ID, organization, admin.ID); n != 1 {
		t.Error("the application doesn't record who created it")
	}
	path := clients + "/" + created.Client.ID.String()
	for _, read := range []string{path, clients} {
		if rec := dbtest.Do(t, asAdmin, http.MethodGet, read, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), created.Secret) {
			t.Errorf("GET %s: %d, or it shows the secret", read, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/organizations/"+otherOrganization.String()+"/oidc/clients", app); rec.Code != http.StatusForbidden {
		t.Errorf("create in another organization: %d, want 403", rec.Code)
	}

	for _, tc := range []struct {
		name string
		body map[string]any
		code string
	}{
		{"a non-loopback http redirect", map[string]any{"redirect_uris": []string{"http://app.example.test/cb"}}, CodeRedirectURIInvalid},
		{"a redirect with userinfo", map[string]any{"redirect_uris": []string{"https://user@app.example.test/cb"}}, CodeRedirectURIInvalid},
		{"no redirect for the code grant", map[string]any{"redirect_uris": []string{}}, CodeRedirectURIInvalid},
		{"an unknown grant", map[string]any{"grant_types": []string{"password"}}, CodeGrantTypeUnsupported},
		{"an exemption past its maximum", map[string]any{"pkce_exempt_until": time.Now().Add(pkceExemptionMax + time.Hour)}, CodePKCEExemptionInvalid},
		{"a back-channel address that isn't http", map[string]any{"backchannel_logout_uri": "ftp://app.example.test/logout"}, errs.CodeBadRequest},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, tc.body); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("PATCH %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.code)
		}
	}
	if got, err := svc.GetClient(ctx, organization, created.Client.ID); err != nil || !slices.Equal(got.RedirectURIs, []string{testRedirect}) || got.BackchannelLogoutURI != "" {
		t.Errorf("client after refused edits: %+v, %v; want it unchanged", got, err)
	}
	var patched Client
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"name": "Portal 2"}), &patched)
	if patched.Name != "Portal 2" || !slices.Equal(patched.RedirectURIs, []string{testRedirect}) {
		t.Errorf("rename: %+v, want the new name and the rest kept", patched)
	}

	var rotated struct {
		Secret string `json:"client_secret"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, path+"/rotate-secret", nil), &rotated)
	if _, err := svc.authenticateClient(ctx, created.Client.ClientID, created.Secret); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
		t.Errorf("the secret before rotation: %v, want %v", err, errs.ErrOIDCClientAuthFailed)
	}
	if _, err := svc.authenticateClient(ctx, created.Client.ClientID, rotated.Secret); rotated.Secret == "" || err != nil {
		t.Errorf("the rotated secret: %v", err)
	}
	var failures ClientAuthFailures
	rec = dbtest.Do(t, asAdmin, http.MethodGet, path+"/auth-failures", nil)
	dbtest.Decode(t, rec, &failures)
	if len(failures.Items) != 1 || failures.Items[0].Reason != "invalid_secret" || failures.LockedUntil != nil || strings.Contains(rec.Body.String(), created.Secret) {
		t.Errorf("auth failures: %s, want the one wrong secret, without it", rec.Body.String())
	}

	rec = dbtest.Do(t, asAdmin, http.MethodPost, clients, map[string]any{"name": "SPA", "type": "public", "redirect_uris": []string{testRedirect}})
	var spa struct {
		Client Client `json:"client"`
	}
	dbtest.Decode(t, rec, &spa)
	if strings.Contains(rec.Body.String(), "client_secret") {
		t.Errorf("a public client was given a secret: %s", rec.Body.String())
	}
	spaPath := clients + "/" + spa.Client.ID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, spaPath+"/rotate-secret", nil); !strings.Contains(rec.Body.String(), CodePublicClientNoSecret) {
		t.Errorf("rotate a public client's secret: %d %s", rec.Code, rec.Body.String())
	}
	exchange := map[string]any{"grant_types": []string{"authorization_code", "token_exchange"}}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, spaPath, exchange); !strings.Contains(rec.Body.String(), CodeUnsupportedFlow) {
		t.Errorf("give a public client token exchange: %d %s", rec.Code, rec.Body.String())
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/oidc/clients/"+created.Client.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.authenticateClient(ctx, created.Client.ClientID, rotated.Secret); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
		t.Errorf("a deleted client authenticated: %v", err)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET a deleted client: %d, want 404", rec.Code)
	}
	for action, want := range map[string]int{
		"oidc.client_registered": 2, "oidc.client_updated": 1, "oidc.client_secret_rotated": 1, "oidc.client_deleted": 1,
	} {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND actor_user_id = $3`, organization, action, admin.ID); n != want {
			t.Errorf("%s audited %d times, want %d", action, n, want)
		}
	}
}

// TestClientChangesKeepTheirAuditRow checks that registering, changing,
// rotating the secret of and deleting an application each commit with an
// audit row naming who did it, and that none of them is kept when its row
// can't be written.
func TestClientChangesKeepTheirAuditRow(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &admin.ID, Type: "user", IP: "192.0.2.41", RequestID: "req-" + uuid.NewString()}

	c, secret, err := svc.CreateClient(ctx, CreateClientInput{OrganizationID: organization, Name: "Web", RedirectURIs: []string{testRedirect}}, actor)
	if err != nil || secret == "" {
		t.Fatalf("create: %v", err)
	}
	if n := recordedBy(t, organization, "oidc.client_registered", c.ID, actor); n != 1 {
		t.Errorf("%d oidc.client_registered rows by the administrator, want 1", n)
	}
	renamed := "Portal"
	if _, err := svc.UpdateClient(ctx, organization, c.ID, UpdateClientInput{Name: &renamed}, actor); err != nil {
		t.Fatalf("update: %v", err)
	}
	if n := recordedBy(t, organization, "oidc.client_updated", c.ID, actor); n != 1 {
		t.Errorf("%d oidc.client_updated rows by the administrator, want 1", n)
	}
	if _, err := svc.RotateClientSecret(ctx, organization, c.ID, actor); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n := recordedBy(t, organization, "oidc.client_secret_rotated", c.ID, actor); n != 1 {
		t.Errorf("%d oidc.client_secret_rotated rows by the administrator, want 1", n)
	}

	hash := func() string {
		var h string
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT client_secret_hash FROM auth.oidc_clients WHERE id = $1`, c.ID).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	before := hash()
	for _, action := range []string{"oidc.client_registered", "oidc.client_updated", "oidc.client_secret_rotated", "oidc.client_deleted"} {
		refuseAudit(t, organization, action)
	}
	if _, _, err := svc.CreateClient(ctx, CreateClientInput{OrganizationID: organization, Name: "Unrecorded", RedirectURIs: []string{testRedirect}}, actor); err == nil {
		t.Error("an application was registered without its audit row")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_clients WHERE organization_id = $1 AND name = 'Unrecorded'`, organization); n != 0 {
		t.Error("the registration stayed when its audit row failed")
	}
	again := "Unrecorded"
	if _, err := svc.UpdateClient(ctx, organization, c.ID, UpdateClientInput{Name: &again}, actor); err == nil {
		t.Error("an application was changed without its audit row")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_clients WHERE id = $1 AND name = 'Portal'`, c.ID); n != 1 {
		t.Error("the change stayed when its audit row failed")
	}
	if _, err := svc.RotateClientSecret(ctx, organization, c.ID, actor); err == nil {
		t.Error("a secret was rotated without its audit row")
	}
	if hash() != before {
		t.Error("the rotated secret stayed when its audit row failed")
	}
	if err := svc.DeleteClient(ctx, organization, c.ID, actor); err == nil {
		t.Error("an application was deleted without its audit row")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_clients WHERE id = $1`, c.ID); n != 1 {
		t.Error("the deletion stayed when its audit row failed")
	}
}
