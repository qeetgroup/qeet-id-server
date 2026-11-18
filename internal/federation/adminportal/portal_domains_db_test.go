//go:build integration

package adminportal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// txtRecords answers every TXT lookup with its records.
// txtRecords answers every TXT lookup with its records, which a test changes
// as it goes.
type txtRecords struct{ records []string }

func (r *txtRecords) LookupTXT(context.Context, string) ([]string, error) { return r.records, nil }

// TestPortalFinishesAnSSOSetup checks that the portal gives the IT admin the
// addresses their IdP needs, begins and reads a test sign-in, and claims and
// verifies domains, as far as the link allows and only for its organization:
// a domain another organization verified stays theirs.
func TestPortalFinishesAnSSOSetup(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	samlService := newSAML(t, everyPlan{})
	dns := &txtRecords{}
	domains := newDomains(t).WithResolver(dns)
	const api = "https://api.example.test"
	h := &Handler{
		Service:       NewService(pool, branded{}, "https://login.example.test"),
		SAML:          samlService,
		SAMLSignIn:    &saml.Handler{Service: samlService, PublicBaseURL: api},
		SCIM:          newSCIM(t),
		Domains:       domains,
		PublicBaseURL: api,
	}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	session := func(capabilities ...string) string {
		t.Helper()
		var out struct {
			Token string `json:"token"`
		}
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/organizations/"+organization.String()+"/admin-portal/links", map[string]any{"capabilities": capabilities}), &out)
		for _, c := range portal(t, public, http.MethodPost, "/admin-portal/session", out.Token, "", nil).Result().Cookies() {
			if c.Name == portalSessionCookie {
				return c.Value
			}
		}
		t.Fatalf("no portal session for %v", capabilities)
		return ""
	}
	everything := session("saml", "scim", "domain_verification")
	samlOnly := session("saml")

	var pc PortalContext
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/context", "", everything, nil), &pc)
	if pc.SCIMBaseURL != api+"/scim/v2" || len(pc.Capabilities) != 3 {
		t.Errorf("context %+v; want the SCIM base URL and all three capabilities", pc)
	}
	pc = PortalContext{}
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/context", "", samlOnly, nil), &pc)
	if pc.SCIMBaseURL != "" || pc.OrganizationName == "" {
		t.Errorf("a SAML-only link's context %+v; want no SCIM base URL", pc)
	}

	// The addresses the IdP needs come with each connection.
	rec := portal(t, public, http.MethodPost, "/admin-portal/saml", "", everything, map[string]string{
		"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso",
		"idp_certificate": idpCertificate(t), "email_attribute": "email",
	})
	var conn saml.Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create a connection: %d %s", rec.Code, rec.Body.String())
	}
	connPath := "/admin-portal/saml/" + conn.ID.String()
	want := saml.SPAddresses{
		EntityID:    api + "/saml/metadata/" + conn.ID.String(),
		ACSURL:      api + "/saml/acs/" + conn.ID.String(),
		MetadataURL: api + "/saml/metadata/" + conn.ID.String(),
	}
	var shown portalConnection
	dbtest.Decode(t, portal(t, public, http.MethodGet, connPath, "", everything, nil), &shown)
	if shown.SPAddresses != want || shown.ID != conn.ID {
		t.Errorf("connection addresses %+v; want %+v", shown.SPAddresses, want)
	}
	var listed struct {
		Items []portalConnection `json:"items"`
	}
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/saml", "", everything, nil), &listed)
	if len(listed.Items) != 1 || listed.Items[0].SPAddresses != want {
		t.Errorf("listed connections %+v; want the one, with its addresses", listed.Items)
	}
	shown = portalConnection{}
	dbtest.Decode(t, portal(t, public, http.MethodPatch, connPath, "", everything, map[string]string{"name": "Okta (staging)"}), &shown)
	if shown.SPAddresses != want || shown.Name != "Okta (staging)" {
		t.Errorf("updated connection %+v; want its addresses", shown)
	}

	// A test sign-in begins in this browser and reads back as pending.
	rec = portal(t, public, http.MethodPost, connPath+"/test-sign-ins", "", everything, nil)
	var test saml.TestSignIn
	dbtest.Decode(t, rec, &test)
	if rec.Code != http.StatusCreated || test.Status != "pending" || test.ConnectionID != conn.ID ||
		!strings.HasPrefix(test.RedirectURL, "https://idp.example.test/sso?SAMLRequest=") {
		t.Fatalf("begin a test sign-in: %d %s", rec.Code, rec.Body.String())
	}
	bound := false
	for _, c := range rec.Result().Cookies() {
		bound = bound || (c.Name == "qe_saml" && c.Value != "")
	}
	if !bound {
		t.Error("the test sign-in isn't bound to the browser")
	}
	var read saml.TestSignIn
	dbtest.Decode(t, portal(t, public, http.MethodGet, connPath+"/test-sign-ins/"+test.ID.String(), "", everything, nil), &read)
	if read.ID != test.ID || read.Status != "pending" || read.RedirectURL != "" {
		t.Errorf("read the test sign-in: %+v; want it pending", read)
	}
	if rec := portal(t, public, http.MethodPost, connPath+"/test-sign-ins", "", session("scim"), nil); !strings.Contains(rec.Body.String(), CodeCapabilityNotGranted) {
		t.Errorf("a test sign-in through a SCIM-only link: %d %s", rec.Code, rec.Body.String())
	}

	// Another organization's connection and its tests are out of reach.
	system := audit.Actor{Type: "system"}
	theirs, err := samlService.Create(ctx, other, saml.CreateInput{
		Name: "Theirs", IdpEntityID: "https://idp.other.test", IdpSSOURL: "https://idp.other.test/sso", IdpCertificate: idpCertificate(t),
	}, system)
	if err != nil {
		t.Fatal(err)
	}
	theirTest, err := h.SAMLSignIn.BeginTestSignIn(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil),
		other, theirs.ID, "https://login.example.test/enterprise-setup", system)
	if err != nil {
		t.Fatal(err)
	}
	theirPath := "/admin-portal/saml/" + theirs.ID.String()
	for name, c := range map[string]struct{ method, path string }{
		"test their connection":                  {http.MethodPost, theirPath + "/test-sign-ins"},
		"read their test":                        {http.MethodGet, theirPath + "/test-sign-ins/" + theirTest.ID.String()},
		"read their test as one's own":           {http.MethodGet, connPath + "/test-sign-ins/" + theirTest.ID.String()},
		"read one's test under their connection": {http.MethodGet, theirPath + "/test-sign-ins/" + test.ID.String()},
	} {
		if rec := portal(t, public, c.method, c.path, "", everything, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d %s, want 404", name, rec.Code, rec.Body.String())
		}
	}

	// Domains: only with the capability, and only the organization's own.
	if rec := portal(t, public, http.MethodGet, "/admin-portal/domains", "", samlOnly, nil); !strings.Contains(rec.Body.String(), CodeCapabilityNotGranted) {
		t.Errorf("domains through a SAML-only link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/domains", "", everything, map[string]string{"domain": "not a domain"}); !strings.Contains(rec.Body.String(), errs.CodeDomainVerifyInvalidDomain) {
		t.Errorf("claim an invalid domain: %d %s", rec.Code, rec.Body.String())
	}
	name := dbtest.Unique("acme") + ".example.test"
	rec = portal(t, public, http.MethodPost, "/admin-portal/domains", "", everything, map[string]string{"domain": "https://" + strings.ToUpper(name) + "/"})
	var claimed domainverify.Domain
	dbtest.Decode(t, rec, &claimed)
	if rec.Code != http.StatusCreated || claimed.Domain != name || claimed.DNSRecordName != "_qeet-verification."+name || claimed.Status != "pending" {
		t.Fatalf("claim a domain: %d %s", rec.Code, rec.Body.String())
	}
	dns.records = []string{claimed.VerificationToken}
	rec = portal(t, public, http.MethodPost, "/admin-portal/domains/"+claimed.ID.String()+"/verify", "", everything, nil)
	var verified domainverify.Domain
	dbtest.Decode(t, rec, &verified)
	if rec.Code != http.StatusOK || verified.Status != "verified" || verified.VerifiedAt == nil {
		t.Errorf("verify the domain: %d %s", rec.Code, rec.Body.String())
	}
	// Single sign-on for the verified domain: on through a link with SAML, never without it.
	var routed domainverify.Domain
	rec = portal(t, public, http.MethodPatch, "/admin-portal/domains/"+claimed.ID.String(), "", everything, map[string]bool{"sso_enabled": true})
	dbtest.Decode(t, rec, &routed)
	if rec.Code != http.StatusOK || !routed.SSOEnabled {
		t.Errorf("turn on SSO for the domain: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodPatch, "/admin-portal/domains/"+claimed.ID.String(), "", session("domain_verification"), map[string]bool{"sso_enabled": false}); !strings.Contains(rec.Body.String(), CodeCapabilityNotGranted) {
		t.Errorf("turn off SSO without SAML in the link: %d %s", rec.Code, rec.Body.String())
	}
	rec = portal(t, public, http.MethodPost, "/admin-portal/domains", "", everything, map[string]string{"domain": dbtest.Domain(t, other)})
	var squat domainverify.Domain
	dbtest.Decode(t, rec, &squat)
	if rec.Code != http.StatusCreated {
		t.Fatalf("claim another organization's verified domain: %d %s", rec.Code, rec.Body.String())
	}
	dns.records = []string{squat.VerificationToken}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/domains/"+squat.ID.String()+"/verify", "", everything, nil); !strings.Contains(rec.Body.String(), errs.CodeDomainVerifyClaimedByOther) {
		t.Errorf("verify a domain another organization verified: %d %s", rec.Code, rec.Body.String())
	}
	elsewhere, err := domains.Add(ctx, other, dbtest.Unique("other")+".example.test", audit.Actor{Type: "system"})
	if err != nil {
		t.Fatal(err)
	}
	dns.records = []string{elsewhere.VerificationToken}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/domains/"+elsewhere.ID.String()+"/verify", "", everything, nil); rec.Code != http.StatusNotFound {
		t.Errorf("verify another organization's domain: %d %s, want 404", rec.Code, rec.Body.String())
	}
	var mine struct {
		Items []domainverify.Domain `json:"items"`
	}
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/domains", "", everything, nil), &mine)
	if len(mine.Items) != 2 {
		t.Errorf("listed %d domains, want the organization's two", len(mine.Items))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.domains WHERE id = $1 AND verified_at IS NULL`, elsewhere.ID); n != 1 {
		t.Error("the portal verified another organization's domain")
	}

	for action, want := range map[string]int{"saml.test_sign_in_started": 1, "domain.created": 2, "domain.verified": 1} {
		if n := dbtest.Count(t, `
			SELECT count(*) FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND actor_type = 'admin_portal' AND actor_user_id = $3
		`, organization, action, admin.ID); n != want {
			t.Errorf("%d %s events recorded as the portal, want %d", n, action, want)
		}
	}
}
