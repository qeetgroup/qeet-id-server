//go:build integration

package adminportal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// branded is an organisation's login branding with only a primary colour.
type branded struct{}

func (branded) LoginBranding(context.Context, uuid.UUID) (string, string, string, string) {
	return "", "#123456", "", ""
}

// idpCertificate returns a throwaway PEM certificate for an identity provider.
func idpCertificate(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// portal sends a request to the public portal with the given bearer token or
// session cookie.
func portal(t *testing.T, h http.Handler, method, path, bearer, session string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, "/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: portalSessionCookie, Value: session})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPortalLinkConfiguresOnlyWhatItGrants checks that an administrator's link
// is redeemed once for a short session, which manages the organisation's SAML
// connections and SCIM token as far as the link allows and no further, and
// that revoking the link or signing out ends it at once.
func TestPortalLinkConfiguresOnlyWhatItGrants(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	users := user.NewRepository(pool)
	h := &Handler{
		Service: NewService(pool, branded{}, "https://login.example.test"),
		SAML:    saml.NewService(pool, auth.NewService(pool, users, dbtest.Issuer(t)), "https://id.example.test"),
		SCIM:    scim.NewService(pool, users),
	}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	links := "/tenants/" + tenant.String() + "/admin-portal/links"

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
	if len(pc.Capabilities) != 1 || pc.Capabilities[0] != "saml" || pc.TenantName == "" || pc.Branding == nil || pc.Branding.PrimaryColor != "#123456" {
		t.Errorf("portal context %+v; want the organisation, its branding and SAML only", pc)
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
	if rec := portal(t, public, http.MethodPost, "/admin-portal/saml", "", session, map[string]string{"name": "Incomplete", "idp_entity_id": "https://idp.example.test"}); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSAMLFieldsRequired) {
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
	if rec := portal(t, public, http.MethodPatch, connPath, "", session, map[string]string{"status": "retired"}); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSAMLStatusInvalid) {
		t.Errorf("an unknown status: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodPatch, connPath, "", session, map[string]string{"status": "active"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"active"`) {
		t.Errorf("activate: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
		t.Errorf("SCIM through a SAML-only link: %d %s", rec.Code, rec.Body.String())
	}

	elsewhere, err := h.SAML.(*saml.Service).List(ctx, other)
	if err != nil || len(elsewhere) != 0 {
		t.Errorf("another organisation's connections %v, %v; want none", elsewhere, err)
	}
	if rec := portal(t, public, http.MethodDelete, connPath, "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete the connection: %d", rec.Code)
	}
	var actions []string
	rows, err := pool.Query(ctx, `SELECT action FROM audit.events WHERE tenant_id = $1 AND actor_type = 'admin_portal' ORDER BY created_at`, tenant)
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
	if rec := portal(t, public, http.MethodGet, "/admin-portal/context", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSessionInvalid) {
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
	if rec := portal(t, public, http.MethodGet, "/admin-portal/saml", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
		t.Errorf("SAML through a SCIM-only link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := portal(t, public, http.MethodDelete, "/admin-portal/session", "", session, nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign out: %d", rec.Code)
	}
	if rec := portal(t, public, http.MethodGet, "/admin-portal/scim", "", session, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalSessionInvalid) {
		t.Errorf("a session after signing out: %d %s", rec.Code, rec.Body.String())
	}

	for name, bearer := range map[string]string{"no token": "", "an unknown token": "forged"} {
		if rec := portal(t, public, http.MethodPost, "/admin-portal/session", bearer, "", nil); rec.Code/100 != 4 {
			t.Errorf("redeem with %s: %d, want refused", name, rec.Code)
		}
	}
	_, token = generate("scim")
	if _, err := pool.Exec(ctx, `UPDATE tenant.admin_portal_links SET expires_at = now() - interval '1 minute' WHERE token_hash = (SELECT token_hash FROM tenant.admin_portal_links WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if rec := portal(t, public, http.MethodPost, "/admin-portal/session", token, "", nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalLinkExpired) {
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
	if rec := dbtest.Do(t, asOther, http.MethodDelete, "/tenants/"+other.String()+"/admin-portal/links/"+list.Items[0].ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation revoking a link: %d, want 404", rec.Code)
	}
}

// txtRecords answers every TXT lookup with its records.
type txtRecords []string

func (r txtRecords) LookupTXT(context.Context, string) ([]string, error) { return r, nil }

// TestPortalFinishesAnSSOSetup checks that the portal gives the IT admin the
// addresses their IdP needs, begins and reads a test sign-in, and claims and
// verifies domains, as far as the link allows and only for its organisation:
// a domain another organisation verified stays theirs.
func TestPortalFinishesAnSSOSetup(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	users := user.NewRepository(pool)
	samlService := saml.NewService(pool, auth.NewService(pool, users, dbtest.Issuer(t)), "https://id.example.test")
	domains := domainverify.NewService(pool)
	const api = "https://api.example.test"
	h := &Handler{
		Service:       NewService(pool, branded{}, "https://login.example.test"),
		SAML:          samlService,
		SAMLSignIn:    &saml.Handler{Service: samlService, PublicBaseURL: api},
		SCIM:          scim.NewService(pool, users),
		Domains:       domains,
		PublicBaseURL: api,
	}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	session := func(capabilities ...string) string {
		t.Helper()
		var out struct {
			Token string `json:"token"`
		}
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/tenants/"+tenant.String()+"/admin-portal/links", map[string]any{"capabilities": capabilities}), &out)
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
	if pc.SCIMBaseURL != "" || pc.TenantName == "" {
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
	if rec := portal(t, public, http.MethodPost, connPath+"/test-sign-ins", "", session("scim"), nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
		t.Errorf("a test sign-in through a SCIM-only link: %d %s", rec.Code, rec.Body.String())
	}

	// Another organisation's connection and its tests are out of reach.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	theirs, err := samlService.Create(ctx, tx, other, saml.CreateInput{
		Name: "Theirs", IdpEntityID: "https://idp.other.test", IdpSSOURL: "https://idp.other.test/sso", IdpCertificate: idpCertificate(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	theirTest, err := h.SAMLSignIn.BeginTestSignIn(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil),
		tx, other, theirs.ID, "https://login.example.test/enterprise-setup")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
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

	// Domains: only with the capability, and only the organisation's own.
	if rec := portal(t, public, http.MethodGet, "/admin-portal/domains", "", samlOnly, nil); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
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
	domains.SetResolver(txtRecords{claimed.VerificationToken})
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
	if rec := portal(t, public, http.MethodPatch, "/admin-portal/domains/"+claimed.ID.String(), "", session("domain_verification"), map[string]bool{"sso_enabled": false}); !strings.Contains(rec.Body.String(), errs.CodeAdminPortalCapabilityNotGranted) {
		t.Errorf("turn off SSO without SAML in the link: %d %s", rec.Code, rec.Body.String())
	}
	rec = portal(t, public, http.MethodPost, "/admin-portal/domains", "", everything, map[string]string{"domain": dbtest.Domain(t, other)})
	var squat domainverify.Domain
	dbtest.Decode(t, rec, &squat)
	if rec.Code != http.StatusCreated {
		t.Fatalf("claim another organisation's verified domain: %d %s", rec.Code, rec.Body.String())
	}
	domains.SetResolver(txtRecords{squat.VerificationToken})
	if rec := portal(t, public, http.MethodPost, "/admin-portal/domains/"+squat.ID.String()+"/verify", "", everything, nil); !strings.Contains(rec.Body.String(), errs.CodeDomainVerifyClaimedByOther) {
		t.Errorf("verify a domain another organisation verified: %d %s", rec.Code, rec.Body.String())
	}
	elsewhere, err := domains.Add(ctx, other, dbtest.Unique("other")+".example.test", audit.Actor{Type: "system"})
	if err != nil {
		t.Fatal(err)
	}
	domains.SetResolver(txtRecords{elsewhere.VerificationToken})
	if rec := portal(t, public, http.MethodPost, "/admin-portal/domains/"+elsewhere.ID.String()+"/verify", "", everything, nil); rec.Code != http.StatusNotFound {
		t.Errorf("verify another organisation's domain: %d %s, want 404", rec.Code, rec.Body.String())
	}
	var mine struct {
		Items []domainverify.Domain `json:"items"`
	}
	dbtest.Decode(t, portal(t, public, http.MethodGet, "/admin-portal/domains", "", everything, nil), &mine)
	if len(mine.Items) != 2 {
		t.Errorf("listed %d domains, want the organisation's two", len(mine.Items))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.domains WHERE id = $1 AND verified_at IS NULL`, elsewhere.ID); n != 1 {
		t.Error("the portal verified another organisation's domain")
	}

	for action, want := range map[string]int{"saml.test_sign_in_started": 1, "domain.created": 2, "domain.verified": 1} {
		if n := dbtest.Count(t, `
			SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = $2 AND actor_type = 'admin_portal' AND actor_user_id = $3
		`, tenant, action, admin.ID); n != want {
			t.Errorf("%d %s events recorded as the portal, want %d", n, action, want)
		}
	}
}

// noSSO is a plan without enterprise SSO.
type noSSO struct{}

func (noSSO) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return false, nil }

// TestPortalSAMLNeedsSSOInThePlan checks that the portal sets up no SAML
// connection for an organisation whose plan doesn't include SSO.
func TestPortalSAMLNeedsSSOInThePlan(t *testing.T) {
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	samlService := saml.NewService(pool, auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t)), "https://id.example.test")
	samlService.SetPlanGate(noSSO{})
	h := &Handler{Service: NewService(pool, branded{}, "https://login.example.test"), SAML: samlService}
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)

	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount), http.MethodPost,
		"/tenants/"+tenant.String()+"/admin-portal/links", map[string]any{"capabilities": []string{"saml"}})
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
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_connections WHERE tenant_id = $1`, tenant); n != 0 {
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
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	users := user.NewRepository(pool)
	h := &Handler{
		Service: NewService(pool, branded{}, "https://login.example.test"),
		SAML:    saml.NewService(pool, auth.NewService(pool, users, dbtest.Issuer(t)), "https://id.example.test"),
	}
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount), http.MethodPost, "/tenants/"+tenant.String()+"/admin-portal/links",
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
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner := dbtest.User(t, tenant, tenant)
	dbtest.Assign(t, owner.ID, tenant, ownerRole)
	if _, err := pool.Exec(ctx, `INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject) VALUES ($1, $2, 'saml', $3, 'okta|owner')`,
		owner.ID, tenant, conn.ID); err != nil {
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
