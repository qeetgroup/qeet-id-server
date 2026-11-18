//go:build integration

package adminportal

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// noSSO is a plan without enterprise SSO.
type noSSO struct{}

func (noSSO) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return false, nil }

// TestPortalSAMLNeedsSSOInThePlan checks that the portal sets up no SAML
// connection for an organization whose plan doesn't include SSO.
func TestPortalSAMLNeedsSSOInThePlan(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	samlService := saml.NewService(pool, auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t)), "https://id.example.test")
	samlService.SetPlanGate(noSSO{})
	h := &Handler{Service: NewService(pool, branded{}, "https://login.example.test"), SAML: samlService}
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)

	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount), http.MethodPost,
		"/organizations/"+organization.String()+"/admin-portal/links", map[string]any{"capabilities": []string{"saml"}})
	var out struct {
		Token string `json:"token"`
	}
	dbtest.Decode(t, rec, &out)
	redeemed := portal(t, public, http.MethodPost, "/admin-portal/session", out.Token, "", nil)
	var session string
	for _, c := range redeemed.Result().Cookies() {
		if c.Name == portalSessionCookie {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatalf("redeem: %d %s", redeemed.Code, redeemed.Body.String())
	}

	rec = portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{
		"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso",
		"idp_certificate": idpCertificate(t),
	})
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("SAML connection on a plan without SSO: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_connections WHERE organization_id = $1`, organization); n != 0 {
		t.Errorf("%d connections created, want none", n)
	}
}

// TestPortalCantChangeTrustOnceAnAdministratorIsLinked checks that a portal
// session, which is no person who could outrank anyone, changes what a SAML
// connection trusts only while no administrator is linked to it: once an
// owner is, a new certificate is refused while other changes still go
// through.
func TestPortalCantChangeTrustOnceAnAdministratorIsLinked(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	users := user.NewRepository(pool)
	h := &Handler{
		Service: NewService(pool, branded{}, "https://login.example.test"),
		SAML:    saml.NewService(pool, auth.NewService(pool, users, dbtest.Issuer(t)), "https://id.example.test"),
	}
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount), http.MethodPost, "/organizations/"+organization.String()+"/admin-portal/links",
		map[string]any{"capabilities": []string{"saml"}, "ttl_seconds": 900})
	var link struct {
		Token string `json:"token"`
	}
	dbtest.Decode(t, rec, &link)
	var session string
	for _, c := range portal(t, public, http.MethodPost, "/admin-portal/session", link.Token, "", nil).Result().Cookies() {
		if c.Name == portalSessionCookie {
			session = c.Value
		}
	}
	rec = portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{
		"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso",
		"idp_certificate": idpCertificate(t), "email_attribute": "email",
	})
	var conn saml.Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create the connection: %d %s", rec.Code, rec.Body.String())
	}
	path := "/admin-portal/saml/" + conn.ID.String()
	if rec := portal(t, public, http.MethodPatch, path, "", session, map[string]string{"idp_certificate": idpCertificate(t)}); rec.Code != http.StatusOK {
		t.Errorf("a new certificate while no administrator is linked: %d %s, want 200", rec.Code, rec.Body.String())
	}

	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner := dbtest.User(t, organization, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject) VALUES ($1, $2, 'saml', $3, 'okta|owner')`,
		owner.ID, organization, conn.ID); err != nil {
		t.Fatal(err)
	}
	if rec := portal(t, public, http.MethodPatch, path, "", session, map[string]string{"idp_certificate": idpCertificate(t)}); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeRBACTrustChangeOutranks) {
		t.Errorf("a new certificate once an owner is linked: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeRBACTrustChangeOutranks)
	}
	if rec := portal(t, public, http.MethodPatch, path, "", session, map[string]string{"name": "Okta (EU)"}); rec.Code != http.StatusOK {
		t.Errorf("a rename once an owner is linked: %d %s, want 200", rec.Code, rec.Body.String())
	}
}
