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

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestApplicationAdministration checks that a client is created in the path's
// organisation whatever the body says, its secret shown once and retired by
// rotation, edits held to the registration rules, wrong secrets listed without
// the secret, and that deleting it stops it authenticating, each audited.
func TestApplicationAdministration(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	clients := "/tenants/" + tenant.String() + "/oidc/clients"
	app := map[string]any{"tenant_id": otherTenant, "name": "Portal", "redirect_uris": []string{testRedirect}}

	rec := dbtest.Do(t, asAdmin, http.MethodPost, clients, app)
	var created struct {
		Client Client `json:"client"`
		Secret string `json:"client_secret"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.Client.TenantID != tenant || created.Secret == "" {
		t.Fatalf("create: %d %s, want a client of the path's organisation and its secret", rec.Code, rec.Body.String())
	}
	path := clients + "/" + created.Client.ID.String()
	for _, read := range []string{path, clients} {
		if rec := dbtest.Do(t, asAdmin, http.MethodGet, read, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), created.Secret) {
			t.Errorf("GET %s: %d, or it shows the secret", read, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/tenants/"+otherTenant.String()+"/oidc/clients", app); rec.Code != http.StatusForbidden {
		t.Errorf("create in another organisation: %d, want 403", rec.Code)
	}

	for _, tc := range []struct {
		name string
		body map[string]any
		code string
	}{
		{"a non-loopback http redirect", map[string]any{"redirect_uris": []string{"http://app.example.test/cb"}}, errs.CodeOIDCRedirectURIInvalid},
		{"a redirect with userinfo", map[string]any{"redirect_uris": []string{"https://user@app.example.test/cb"}}, errs.CodeOIDCRedirectURIInvalid},
		{"no redirect for the code grant", map[string]any{"redirect_uris": []string{}}, errs.CodeOIDCRedirectURIInvalid},
		{"an unknown grant", map[string]any{"grant_types": []string{"password"}}, errs.CodeOIDCGrantTypeUnsupported},
		{"an exemption past its maximum", map[string]any{"pkce_exempt_until": time.Now().Add(pkceExemptionMax + time.Hour)}, errs.CodeOIDCPKCEExemptionInvalid},
		{"a back-channel address that isn't http", map[string]any{"backchannel_logout_uri": "ftp://app.example.test/logout"}, errs.CodeBadRequest},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, tc.body); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("PATCH %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.code)
		}
	}
	if got, err := svc.GetClient(ctx, tenant, created.Client.ID); err != nil || !slices.Equal(got.RedirectURIs, []string{testRedirect}) || got.BackchannelLogoutURI != "" {
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
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, spaPath+"/rotate-secret", nil); !strings.Contains(rec.Body.String(), errs.CodeOIDCPublicClientNoSecret) {
		t.Errorf("rotate a public client's secret: %d %s", rec.Code, rec.Body.String())
	}
	exchange := map[string]any{"grant_types": []string{"authorization_code", "token_exchange"}}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, spaPath, exchange); !strings.Contains(rec.Body.String(), errs.CodeOIDCUnsupportedFlow) {
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
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2 AND actor_user_id = $3`, tenant, action, admin.ID); n != want {
			t.Errorf("%s audited %d times, want %d", action, n, want)
		}
	}
}

// TestResourcesAndShadowAIReview checks that an organisation registers each
// resource once, served only by one of its own applications, which may then
// introspect tokens for it where another may not, and that an unreviewed
// machine application is listed until an admin reviews it.
func TestResourcesAndShadowAIReview(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	client, secret := registerClient(t, svc, tenant)
	server, serverSecret := registerClient(t, svc, tenant)
	bystander, bystanderSecret := registerClient(t, svc, tenant)
	foreign, _ := registerClient(t, svc, otherTenant)
	resources := "/tenants/" + tenant.String() + "/oidc/resources"

	for _, tc := range []struct {
		name string
		body map[string]any
		code string
	}{
		{"served by another organisation's application", map[string]any{"identifier": resourceA, "server_client_id": foreign.ClientID}, errs.CodeOIDCClientNotFound},
		{"a relative identifier", map[string]any{"identifier": "api/orders"}, errs.CodeOIDCResourceInvalid},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, resources, tc.body); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("register a resource %s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.code)
		}
	}
	var res Resource
	rec := dbtest.Do(t, asAdmin, http.MethodPost, resources, map[string]any{"identifier": resourceA, "name": "Orders", "server_client_id": server.ClientID})
	dbtest.Decode(t, rec, &res)
	if rec.Code != http.StatusCreated || res.ServerClientID != server.ClientID {
		t.Fatalf("register a resource: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, resources, map[string]any{"identifier": resourceA}); !strings.Contains(rec.Body.String(), errs.CodeOIDCResourceExists) {
		t.Errorf("register it again: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, resources, nil)); !slices.Equal(ids, []uuid.UUID{res.ID}) {
		t.Errorf("resources %v, want only %s", ids, res.ID)
	}

	issued := redeemCode(t, svc, client, secret, admin.ID, resourceA)
	if out, err := svc.Introspect(ctx, server.ClientID, serverSecret, issued.AccessToken, ""); err != nil || out["active"] != true || out["resource"] != resourceA {
		t.Errorf("the resource's server introspecting its token: %v, %v; want it active, for the resource", out, err)
	}
	if out, err := svc.Introspect(ctx, bystander.ClientID, bystanderSecret, issued.AccessToken, ""); err != nil || out["active"] != false {
		t.Errorf("an application serving no resource introspecting the token: %v, %v; want inactive", out, err)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, resources+"/"+res.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove the resource: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, resources+"/"+res.ID.String(), nil); !strings.Contains(rec.Body.String(), errs.CodeOIDCResourceNotFound) {
		t.Errorf("remove it again: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("a grant for a removed resource renewed")
	}

	machine, _ := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, Name: "Agent", GrantTypes: []string{"client_credentials"}})
	shadow := "/tenants/" + tenant.String() + "/oidc/clients/shadow-ai"
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, shadow, nil)); !slices.Equal(ids, []uuid.UUID{machine.ID}) {
		t.Errorf("shadow-AI candidates %v, want only the machine application %s", ids, machine.ID)
	}
	review := "/tenants/" + tenant.String() + "/oidc/clients/"
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, review+foreign.ID.String()+"/review", nil); rec.Code != http.StatusNotFound {
		t.Errorf("review another organisation's application: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, review+machine.ID.String()+"/review", nil); rec.Code != http.StatusNoContent {
		t.Errorf("review: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, shadow, nil)); len(ids) != 0 {
		t.Errorf("shadow-AI candidates after review %v, want none", ids)
	}
}

// TestGrantAdministration checks that an organisation's admin sees the live
// grants its people have given applications and can end one, every rotation
// included, and can neither see nor end another organisation's.
func TestGrantAdministration(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	person := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, otherTenant, otherTenant)
	h := (&Handler{Service: svc}).Mount
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h)
	asOutsider := dbtest.Serve(dbtest.Principal(outsider.ID, otherTenant), h)
	client, secret := registerClient(t, svc, tenant)
	first := redeemCode(t, svc, client, secret, person.ID, "")
	rotated, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	grants := "/tenants/" + tenant.String() + "/oauth/grants"

	var page struct {
		Items []Grant `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, grants, nil), &page)
	if len(page.Items) != 1 || page.Items[0].ClientID != client.ClientID || page.Items[0].UserEmail != person.Email {
		t.Fatalf("grants %+v, want the person's one live grant", page.Items)
	}
	grant := page.Items[0].ID.String()
	if rec := dbtest.Do(t, asOutsider, http.MethodGet, grants, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation listing the grants: %d, want 403", rec.Code)
	}
	inOther := "/tenants/" + otherTenant.String() + "/oauth/grants/" + grant
	if rec := dbtest.Do(t, asOutsider, http.MethodDelete, inOther, nil); !strings.Contains(rec.Body.String(), errs.CodeOIDCGrantNotFound) {
		t.Errorf("another organisation ending the grant: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, grants+"/"+grant, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("end the grant: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, rotated.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Errorf("refresh after the grant ended: %v, want %v", err, errs.ErrOIDCRefreshTokenRevoked)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, grants, nil)); len(ids) != 0 {
		t.Errorf("grants after ending it %v, want none", ids)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'oauth.grant_revoked' AND resource_id = $2`, tenant, person.ID); n != 1 {
		t.Errorf("ending the grant was audited %d times, want once", n)
	}
}
