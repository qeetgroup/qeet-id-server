//go:build integration

package adminportal

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPortalLinkConfiguresOnlyWhatItGrants checks that an administrator's link
// is redeemed once for a short session, which manages the organization's SAML
// connections and SCIM token as far as the link allows and no further, and
// that revoking the link or signing out ends it at once.
func TestPortalLinkConfiguresOnlyWhatItGrants(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := &Handler{
		Service: NewService(pool, branded{}, "https://login.example.test"),
		SAML:    newSAML(t, everyPlan{}),
		SCIM:    newSCIM(t),
	}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	links := "/organizations/" + organization.String() + "/admin-portal/links"

	generate := func(capabilities ...string) (uuid.UUID, string) {
		t.Helper()
		rec := dbtest.Do(t, asAdmin, http.MethodPost, links, map[string]any{"capabilities": capabilities, "ttl_seconds": 900})
		var out struct {
			Link  Link   `json:"link"`
			Token string `json:"token"`
			URL   string `json:"url"`
		}
		dbtest.Decode(t, rec, &out)
		if rec.Code != http.StatusCreated || out.URL != "https://login.example.test/enterprise-setup#token="+out.Token {
			t.Fatalf("generate: %d %s", rec.Code, rec.Body.String())
		}
		if ttl := time.Until(out.Link.ExpiresAt); ttl < 14*time.Minute || ttl > 16*time.Minute {
			t.Errorf("a one-minute link lasts %v, want the 15-minute minimum", ttl)
		}
		return out.Link.ID, out.Token
	}
	redeem := func(token string) string {
		t.Helper()
		rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("redeem: %d %s", rec.Code, rec.Body.String())
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == portalSessionCookie {
				return c.Value
			}
		}
		t.Fatal("redeem set no session cookie")
		return ""
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, links, map[string]any{"capabilities": []string{"billing"}}); rec.Code/100 != 4 {
		t.Errorf("a link for an unknown capability: %d, want refused", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, links, map[string]any{"capabilities": []string{"saml"}, "ttl_seconds": 60}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "adminportal.ttl_out_of_range") {
		t.Errorf("a link lasting a minute: %d %s, want 422 ttl_out_of_range", rec.Code, rec.Body.String())
	}

	linkID, token := generate("saml", "SAML")
	session := redeem(token)
	if rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil); rec.Code/100 != 4 {
		t.Errorf("redeeming a link twice: %d, want refused", rec.Code)
	}
	var pc PortalContext
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/context", "", session, nil), &pc)
	if len(pc.Capabilities) != 1 || pc.Capabilities[0] != "saml" || pc.OrganizationName == "" || pc.Branding == nil || pc.Branding.PrimaryColor != "#123456" {
		t.Errorf("portal context %+v; want the organization, its branding and SAML only", pc)
	}

	rec := portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{
		"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso",
		"idp_certificate": idpCertificate(t), "email_attribute": "email",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create SAML connection: %d %s", rec.Code, rec.Body.String())
	}
	var conn saml.Connection
	dbtest.Decode(t, rec, &conn)
	// A name alone is a draft, answered with the addresses the IdP needs before its details exist;
	// a detail without the rest is refused.
	var draft struct {
		saml.Connection
		saml.SPAddresses
	}
	rec = portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{"name": "Okta draft"})
	dbtest.Decode(t, rec, &draft)
	if rec.Code != http.StatusCreated || draft.Status != "draft" || draft.ACSURL == "" || draft.EntityID == "" {
		t.Errorf("a name-only draft: %d %s, want 201 draft with its addresses", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{"name": "Incomplete", "idp_entity_id": "https://idp.example.test"}); !strings.Contains(rec.Body.String(), CodeSAMLFieldsRequired) {
		t.Errorf("an incomplete connection: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodDelete, "/admin-portal/saml/"+draft.ID.String(), "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("remove the draft: %d %s", rec.Code, rec.Body.String())
	}
	connPath := "/admin-portal/saml/" + conn.ID.String()
	if rec := portal(t, public, http.MethodGet, "/admin-portal/saml", "", session, nil); !strings.Contains(rec.Body.String(), conn.ID.String()) {
		t.Errorf("SAML connections: %s", rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, connPath, "", session, nil); rec.Code != http.StatusOK {
		t.Errorf("get the connection: %d", rec.Code)
	}
	var result saml.TestResult
	dbtest.Decode(t, portal(t, public, http.MethodPost, connPath+"/test", "", session, nil), &result)
	if !result.OK {
		t.Errorf("preflight of a complete connection: %+v", result)
	}
	if rec := portal(t, public, http.MethodPatch, connPath, "", session, map[string]string{"status": "retired"}); !strings.Contains(rec.Body.String(), CodeSAMLStatusInvalid) {
		t.Errorf("an unknown status: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodPatch, connPath, "", session, map[string]string{"status": "active"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"active"`) {
		t.Errorf("activate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); !strings.Contains(rec.Body.String(), CodeCapabilityNotGranted) {
		t.Errorf("SCIM through a SAML-only link: %d %s", rec.Code, rec.Body.String())
	}

	elsewhere, err := h.SAML.List(ctx, other)
	if err != nil || len(elsewhere) != 0 {
		t.Errorf("another organization's connections %v, %v; want none", elsewhere, err)
	}
	if rec := portal(t, public, http.MethodDelete, connPath, "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete the connection: %d", rec.Code)
	}
	var actions []string
	rows, err := pool.Query(ctx, `SELECT action FROM audit.events WHERE organization_id = $1 AND actor_type = 'admin_portal' ORDER BY created_at`, organization)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	// The connection, the draft made and removed, then the connection activated and deleted.
	want := "saml.connection_created,saml.connection_created,saml.connection_deleted,saml.connection_updated,saml.connection_deleted"
	if strings.Join(actions, ",") != want {
		t.Errorf("recorded %v; want each change, as the portal", actions)
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, links+"/"+linkID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/context", "", session, nil); !strings.Contains(rec.Body.String(), CodeSessionInvalid) {
		t.Errorf("a session after its link was revoked: %d %s", rec.Code, rec.Body.String())
	}

	_, token = generate("scim")
	session = redeem(token)
	rec = portal(t, public, http.MethodPost, "/admin-portal/scim/token", "", session, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"token_set":true`) {
		t.Fatalf("rotate the SCIM token: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); strings.Contains(rec.Body.String(), `"token":`) {
		t.Errorf("the SCIM settings returned the token: %s", rec.Body.String())
	}
	if rec := portal(t, public, http.MethodDelete, "/admin-portal/scim/token", "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("revoke the SCIM token: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/saml", "", session, nil); !strings.Contains(rec.Body.String(), CodeCapabilityNotGranted) {
		t.Errorf("SAML through a SCIM-only link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodDelete, "/admin-portal/session", "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign out: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); !strings.Contains(rec.Body.String(), CodeSessionInvalid) {
		t.Errorf("a session after signing out: %d %s", rec.Code, rec.Body.String())
	}

	for name, bearer := range map[string]string{"no token": "", "an unknown token": "forged"} {
		if rec := portal(t, public, http.MethodPost, "/admin-portal/session", bearer, "", nil); rec.Code/100 != 4 {
			t.Errorf("redeem with %s: %d, want refused", name, rec.Code)
		}
	}
	_, token = generate("scim")
	if _, err := pool.Exec(ctx, `UPDATE organization.admin_portal_links SET expires_at = now() - interval '1 minute' WHERE token_hash = (SELECT token_hash FROM organization.admin_portal_links WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1)`, organization); err != nil {
		t.Fatal(err)
	}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil); !strings.Contains(rec.Body.String(), CodeLinkExpired) {
		t.Errorf("redeem an expired link: %d %s", rec.Code, rec.Body.String())
	}

	var list struct {
		Items []Link `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, links, nil), &list)
	if len(list.Items) != 3 {
		t.Errorf("%d links listed, want 3", len(list.Items))
	}
	otherAdmin := dbtest.User(t, other, other)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	if rec := dbtest.Do(t, asOther, http.MethodDelete, "/organizations/"+other.String()+"/admin-portal/links/"+list.Items[0].ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization revoking a link: %d, want 404", rec.Code)
	}
}
