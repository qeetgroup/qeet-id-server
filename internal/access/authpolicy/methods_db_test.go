//go:build integration

package authpolicy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestUsageCountsHowPeopleSignIn checks that the usage counts the
// organization's live people by way of signing in, and those each way alone
// lets in, and leaves out other organizations' people.
func TestUsageCountsHowPeopleSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	passwordOnly, both, passkeyOnly, googleOnly := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	elsewhere := dbtest.User(t, other, other)
	for _, u := range []uuid.UUID{passwordOnly.ID, both.ID, elsewhere.ID} {
		dbtest.SetPassword(t, u, "Kx7mQ2vLp9Wz")
	}
	for _, u := range []uuid.UUID{both.ID, passkeyOnly.ID} {
		if _, err := pool.Exec(ctx, `INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count) VALUES ($1, $2, $3, 0)`,
			u, []byte(uuid.NewString()), []byte("key")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.social_providers (organization_id, provider, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, 'google', 'cid', '\x00', '\x00')`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, subject) VALUES ($1, $2, 'google', $3), ($4, $2, 'google', $5)`,
		googleOnly.ID, organization, uuid.NewString(), both.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: newService(t)}).Mount)
	var got MethodUsage
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/auth-policy/usage", nil), &got)
	if got.People != 5 || got.Password != (MethodCount{People: 2, Only: 1}) || got.Passkey != (MethodCount{People: 2, Only: 1}) {
		t.Errorf("usage %+v; want 5 people, 2 with a password (1 only), 2 with a passkey (1 only)", got)
	}
	if len(got.Social) != 1 || got.Social[0] != (SocialCount{Provider: "google", Linked: 2, Only: 1}) || !got.MagicLinkEnabled {
		t.Errorf("social %+v, magic link %v; want google with 2 linked, 1 only, and magic links on", got.Social, got.MagicLinkEnabled)
	}
}

// TestEveryMethodOffNeedsSingleSignOn checks that an organization may switch
// every first-factor method off only while it has an active SAML or LDAP
// connection of its own: a draft or disabled one, or another organization's
// active one, doesn't count.
func TestEveryMethodOffNeedsSingleSignOn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	path := "/organizations/" + organization.String() + "/auth-policy"
	ssoOnly := map[string]any{"password_enabled": false, "passkey_enabled": false, "magic_link_enabled": false}
	refused := func(when string) {
		t.Helper()
		if rec := dbtest.Do(t, h, http.MethodPut, path, ssoOnly); rec.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(rec.Body.String(), `"code":"no_sign_in_method"`) {
			t.Errorf("every method off %s: %d %s, want 422 no_sign_in_method", when, rec.Code, rec.Body.String())
		}
	}
	saml := func(organization uuid.UUID, status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
			VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', $2)
		`, organization, status); err != nil {
			t.Fatal(err)
		}
	}

	refused("with no connection")
	saml(organization, "draft")
	saml(organization, "disabled")
	saml(other, "active")
	refused("with a draft and a disabled connection, and another organization's active one")

	if _, err := pool.Exec(ctx, `
		INSERT INTO organization.ldap_connections (organization_id, name, server_url, bind_dn, bind_password_ct, bind_password_nonce, base_dn, status)
		VALUES ($1, 'Directory', 'ldaps://ldap.example.test', 'cn=service', '\x00', '\x00', 'dc=example', 'active')
	`, organization); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, h, http.MethodPut, path, ssoOnly); rec.Code != http.StatusOK {
		t.Fatalf("every method off with an active LDAP connection: %d %s", rec.Code, rec.Body.String())
	}
	if m, err := svc.SignInMethodsFor(ctx, organization); err != nil || m != (SignInMethods{}) {
		t.Errorf("sign-in methods of a single-sign-on-only organization: %+v, %v; want none", m, err)
	}
}

// TestEveryMethodOffWithOpenIDConnect checks that an active OpenID Connect
// connection lets an organization switch every other method off, as SAML and
// LDAP do, and a draft one doesn't.
func TestEveryMethodOffWithOpenIDConnect(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: newService(t)}).Mount)
	path := "/organizations/" + organization.String() + "/auth-policy"
	ssoOnly := map[string]any{"password_enabled": false, "passkey_enabled": false, "magic_link_enabled": false}
	connect := func(status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO organization.oidc_connections (organization_id, name, issuer, client_id, client_secret_ct, client_secret_nonce, status)
			VALUES ($1, 'Entra ID', 'https://login.example.test', 'client', '\x00', '\x00', $2)`, organization, status); err != nil {
			t.Fatal(err)
		}
	}
	connect("draft")
	if rec := dbtest.Do(t, h, http.MethodPut, path, ssoOnly); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("every method off with a draft OpenID Connect connection: %d, want 422", rec.Code)
	}
	connect("active")
	if rec := dbtest.Do(t, h, http.MethodPut, path, ssoOnly); rec.Code != http.StatusOK {
		t.Errorf("every method off with an active OpenID Connect connection: %d %s", rec.Code, rec.Body.String())
	}
}
