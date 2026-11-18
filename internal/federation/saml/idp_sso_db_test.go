//go:build integration

package saml

// Database tests for the organization's SAML IdP issuing assertions, with the
// hosted-login session resolved by the real authentication service.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// metadataCertRe finds the signing certificate in IdP metadata.
var metadataCertRe = regexp.MustCompile(`<X509Certificate>([^<]+)</X509Certificate>`)

// idpSide is the organization-facing IdP, its public routes and a way to open
// a hosted-login session.
type idpSide struct {
	idp    *IdP
	router chi.Router
	signIn func(userID uuid.UUID) string
}

// newIdPSide returns the IdP, resolving hosted-login sessions with the real
// authentication service.
func newIdPSide(t *testing.T) *idpSide {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(pool, keyPEM, certPEM, "https://login.id.qeet.in", authSvc)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	(&Handler{Service: &Service{}, IdP: idp, PublicBaseURL: testPublicBase}).MountPublic(router)
	signIn := func(userID uuid.UUID) string {
		raw, err := authSvc.CreateLoginSession(dbtest.Context(t), userID, "203.0.113.7", "test")
		if err != nil {
			t.Fatalf("hosted-login session: %v", err)
		}
		return raw
	}
	return &idpSide{idp: idp, router: router, signIn: signIn}
}

// authnRequestTo is a Redirect-binding SAMLRequest query from issuer, asking
// for the assertion at acs ("" leaves the registered one).
func authnRequestTo(issuer, id, acs string) string {
	raw := `<samlp:AuthnRequest xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `" ID="` + id + `"`
	if acs != "" {
		raw += ` AssertionConsumerServiceURL="` + acs + `"`
	}
	raw += `><saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
	return "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(fuzzDeflate(raw)))
}

// setSPStatus changes a service provider's status.
func setSPStatus(t *testing.T, ctx context.Context, idp *IdP, sp *ServiceProvider, status string) {
	t.Helper()
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := idp.updateSP(ctx, tx, sp.ID, sp.OrganizationID, UpdateSPInput{Status: &status}); err != nil {
		t.Fatalf("set the SP %s: %v", status, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestIdPSignInNeedsSSOInThePlan checks that a service provider registered
// while the plan had SSO gets no assertion once the plan has lapsed.
func TestIdPSignInNeedsSSOInThePlan(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	organization := dbtest.Organization(t)
	member := dbtest.User(t, organization, organization)
	sp := registerSP(t, ctx, s.idp, organization, "https://sp.example.test/metadata", "https://sp.example.test/acs")
	allowed := map[uuid.UUID]bool{organization: true}
	s.idp.SetPlanGate(poolGate{pool: dbtest.Pool(t), allowed: allowed})
	sso := "/saml/idp/" + organization.String() + "/sso?" + authnRequestTo(sp.EntityID, "_req-1", sp.ACSURL)
	cookie := s.signIn(member.ID)

	if acs, _ := postedTo(t, idpGet(t, s.router, sso, cookie)); acs != sp.ACSURL {
		t.Fatalf("SSO on a plan with SSO posted to %q, want %q", acs, sp.ACSURL)
	}
	delete(allowed, organization) // the plan lapses
	if rec := idpGet(t, s.router, sso, cookie); rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("SSO after the plan lapsed: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}
}

// TestIdPIssuesAssertionsAsRegistered checks that the organization's IdP
// issues a recorded assertion, which a standard SP verifies with the metadata's
// certificate, only to an enabled, registered SP at its ACS URL for a signed-in
// person of the organization; anyone else is refused or sent to sign in.
func TestIdPIssuesAssertionsAsRegistered(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	member := dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, other, other)
	cookie := s.signIn(member.ID)
	sp := registerSP(t, ctx, s.idp, organization, "https://sp.example.test/metadata", "https://sp.example.test/acs")
	prefix := "/saml/idp/" + organization.String()
	issuer := testPublicBase + prefix

	meta := idpGet(t, s.router, prefix+"/metadata", "")
	published := metadataCertRe.FindStringSubmatch(meta.Body.String())
	if meta.Code != http.StatusOK || published == nil {
		t.Fatalf("metadata: %d %s; want the signing certificate", meta.Code, meta.Body.String())
	}
	cert, err := parseCertificate(published[1])
	if err != nil {
		t.Fatalf("published certificate: %v", err)
	}

	rec := idpGet(t, s.router, prefix+"/sso?"+authnRequestTo(sp.EntityID, "_req-1", sp.ACSURL)+"&RelayState=state-1", cookie)
	if acs, got := postedTo(t, rec); acs != sp.ACSURL || got != issuer {
		t.Errorf("SSO posted to %q as %q, want %q as %q", acs, got, sp.ACSURL, issuer)
	}
	if !strings.Contains(rec.Body.String(), `name="RelayState" value="state-1"`) {
		t.Errorf("SSO lost the RelayState: %s", rec.Body.String())
	}
	verifier := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      issuer,
		ServiceProviderIssuer:       sp.EntityID,
		AssertionConsumerServiceURL: sp.ACSURL,
		AudienceURI:                 sp.EntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
	}
	info, err := verifier.RetrieveAssertionInfo(html.UnescapeString(samlResponseRe.FindStringSubmatch(rec.Body.String())[1]))
	if err != nil {
		t.Fatalf("a standard SP refused the assertion: %v", err)
	}
	if info.WarningInfo.InvalidTime || info.WarningInfo.NotInAudience || info.NameID != member.Email ||
		info.Assertions[0].Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != "_req-1" {
		t.Errorf("assertion for %q, warnings %+v; want the member, answering _req-1, valid now for the SP", info.NameID, info.WarningInfo)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'saml.idp_assertion_issued' AND resource_id = $2 AND actor_user_id = $3`, organization, sp.ID, member.ID); n != 1 {
		t.Errorf("%d issued assertions recorded, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_service_providers WHERE id = $1 AND last_login_at IS NOT NULL`, sp.ID); n != 1 {
		t.Error("the SP's last sign-in was not recorded")
	}

	for _, c := range []struct {
		name, query, cookie, want string
	}{
		{"an attacker's ACS URL", authnRequestTo(sp.EntityID, "_req-2", "https://evil.example.test/acs"), cookie, CodeACSMismatch},
		{"an unregistered SP", authnRequestTo("https://unknown.example.test", "_req-3", ""), cookie, errs.CodeNotFound},
		{"an unreadable request", "SAMLRequest=" + url.QueryEscape("not base64!"), cookie, CodeAuthnRequestInvalid},
		{"neither a request nor an SP", "RelayState=state-1", cookie, CodeRequestParamMissing},
		{"another organization's person", "sp=" + sp.ID.String(), s.signIn(outsider.ID), CodeUserOrganizationMismatch},
	} {
		rec := idpGet(t, s.router, prefix+"/sso?"+c.query, c.cookie)
		if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), c.want) || strings.Contains(rec.Body.String(), "SAMLResponse") {
			t.Errorf("%s: %d %s, want %s", c.name, rec.Code, rec.Body.String(), c.want)
		}
	}

	for _, c := range []string{"", "not-a-session"} {
		rec := idpGet(t, s.router, prefix+"/sso?sp="+sp.ID.String(), c)
		login, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || err != nil || !strings.HasPrefix(login.String(), "https://login.id.qeet.in/sign-in?") ||
			login.Query().Get("return_to") != issuer+"/sso?sp="+sp.ID.String() {
			t.Errorf("SSO with session %q: %d %s; want the hosted login, returning here", c, rec.Code, rec.Header().Get("Location"))
		}
	}

	setSPStatus(t, ctx, s.idp, sp, "disabled")
	if rec := idpGet(t, s.router, prefix+"/sso?sp="+sp.ID.String(), cookie); !strings.Contains(rec.Body.String(), CodeServiceProviderDisabled) {
		t.Errorf("SSO to a disabled SP by ID: %d %s, want %s", rec.Code, rec.Body.String(), CodeServiceProviderDisabled)
	}
	if rec := idpGet(t, s.router, prefix+"/sso?"+authnRequestTo(sp.EntityID, "_req-4", ""), cookie); rec.Code != http.StatusNotFound {
		t.Errorf("a request from a disabled SP: %d %s, want 404", rec.Code, rec.Body.String())
	}

	// A draft app signs no one in, whichever way the sign-in starts, and an
	// attempt by someone signed in is audited.
	setSPStatus(t, ctx, s.idp, sp, "draft")
	for _, c := range []struct{ name, query, cookie string }{
		{"by ID, signed in", "sp=" + sp.ID.String(), cookie},
		{"by ID, not signed in", "sp=" + sp.ID.String(), ""},
		{"from the SP", authnRequestTo(sp.EntityID, "_req-5", ""), cookie},
	} {
		rec := idpGet(t, s.router, prefix+"/sso?"+c.query, c.cookie)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeServiceProviderDraft) || strings.Contains(rec.Body.String(), "SAMLResponse") {
			t.Errorf("SSO to a draft SP %s: %d %s, want 403 %s", c.name, rec.Code, rec.Body.String(), CodeServiceProviderDraft)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'saml.idp_assertion_refused' AND resource_id = $2
		AND metadata->>'reason' = 'draft'`, organization, sp.ID); n != 2 {
		t.Errorf("%d refused sign-ins to the draft SP recorded, want the 2 by a signed-in person", n)
	}

	bare := chi.NewRouter()
	(&Handler{Service: &Service{}}).MountPublic(bare)
	for _, path := range []string{prefix + "/metadata", prefix + "/sso?sp=" + sp.ID.String()} {
		if rec := idpGet(t, bare, path, cookie); !strings.Contains(rec.Body.String(), CodeIdPNotConfigured) {
			t.Errorf("%s without an IdP: %d %s, want %s", path, rec.Code, rec.Body.String(), CodeIdPNotConfigured)
		}
	}
}

// TestIdPRefusesASuspendedAccount checks that once a person is suspended the
// organization's IdP issues no assertion for them, though their hosted-login
// session is still open.
func TestIdPRefusesASuspendedAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	organization := dbtest.Organization(t)
	member := dbtest.User(t, organization, organization)
	cookie := s.signIn(member.ID)
	sp := registerSP(t, ctx, s.idp, organization, "https://sp.example.test/metadata", "https://sp.example.test/acs")
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	rec := idpGet(t, s.router, "/saml/idp/"+organization.String()+"/sso?sp="+sp.ID.String(), cookie)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Errorf("SSO for a suspended account: %d, want refused", rec.Code)
	}
}

// TestIdPSameEntityIDInTwoOrganizations checks that two organizations registering the same
// SP entity ID each get their own SP configuration and IdP identity.
func TestIdPSameEntityIDInTwoOrganizations(t *testing.T) {
	ctx := dbtest.Context(t)
	const entityID = "https://sp.example.com/saml/metadata"
	sessions := sessionsByCookie{}
	idp, router := newIdPRouter(t, sessions)

	var fixtures []idpOrganizationFixture
	for i := range 2 {
		organizationID := dbtest.Organization(t)
		member := dbtest.User(t, organizationID)
		cookie := "session-" + uuid.NewString()
		sessions[cookie] = member.ID
		acs := "https://sp.example.com/acs/" + string(rune('a'+i))
		fixtures = append(fixtures, idpOrganizationFixture{organizationID, cookie, registerSP(t, ctx, idp, organizationID, entityID, acs)})
	}

	for _, f := range fixtures {
		prefix := "/saml/idp/" + f.organizationID.String()
		wantIssuer := testPublicBase + prefix

		acs, issuer := postedTo(t, idpGet(t, router, prefix+"/sso?"+authnRequestQuery(entityID, "_req-1"), f.cookie))
		if acs != f.sp.ACSURL || issuer != wantIssuer {
			t.Errorf("SP-initiated SSO for %s posted to %q as %q, want %q as %q", f.organizationID, acs, issuer, f.sp.ACSURL, wantIssuer)
		}
		for _, ref := range []string{url.QueryEscape(entityID), f.sp.ID.String()} {
			acs, issuer = postedTo(t, idpGet(t, router, prefix+"/sso?sp="+ref, f.cookie))
			if acs != f.sp.ACSURL || issuer != wantIssuer {
				t.Errorf("IdP-initiated SSO (sp=%s) for %s posted to %q as %q, want %q as %q", ref, f.organizationID, acs, issuer, f.sp.ACSURL, wantIssuer)
			}
		}

		meta := idpGet(t, router, prefix+"/metadata", "")
		if meta.Code != http.StatusOK ||
			!strings.Contains(meta.Body.String(), `entityID="`+wantIssuer+`"`) ||
			!strings.Contains(meta.Body.String(), `Location="`+wantIssuer+`/sso"`) {
			t.Errorf("metadata for %s = %d %s, want entity %s", f.organizationID, meta.Code, meta.Body.String(), wantIssuer)
		}
	}

	// One organization's SSO endpoint never resolves another organization's SP by its ID.
	a, b := fixtures[0], fixtures[1]
	if rec := idpGet(t, router, "/saml/idp/"+a.organizationID.String()+"/sso?sp="+b.sp.ID.String(), a.cookie); rec.Code != http.StatusNotFound {
		t.Errorf("organization A SSO with organization B's SP ID = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

// TestIdPUnknownOrInactiveOrganization checks that an unknown, malformed or
// suspended organization gets the same answer as an unknown SP.
func TestIdPUnknownOrInactiveOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	_, router := newIdPRouter(t, sessionsByCookie{})
	active := dbtest.Organization(t)
	suspended := dbtest.Organization(t)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, suspended); err != nil {
		t.Fatal(err)
	}

	unknownSP := idpGet(t, router, "/saml/idp/"+active.String()+"/sso?sp="+url.QueryEscape("https://unknown.example"), "")
	if unknownSP.Code != http.StatusNotFound {
		t.Fatalf("unknown SP = %d %s, want 404", unknownSP.Code, unknownSP.Body.String())
	}
	for _, organization := range []string{suspended.String(), uuid.NewString(), "not-a-uuid"} {
		for _, path := range []string{"/metadata", "/sso?sp=" + url.QueryEscape("https://unknown.example")} {
			rec := idpGet(t, router, "/saml/idp/"+organization+path, "")
			if rec.Code != unknownSP.Code || rec.Body.String() != unknownSP.Body.String() {
				t.Errorf("organization %s %s = %d %s, want the unknown-SP answer %d %s",
					organization, path, rec.Code, rec.Body.String(), unknownSP.Code, unknownSP.Body.String())
			}
		}
	}
}

// TestIdPPostBindingResumesAfterSignIn checks that an HTTP-POST binding
// AuthnRequest arriving without a hosted-login session is answered, once the
// person has signed in, at the URL the login returns to.
func TestIdPPostBindingResumesAfterSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	const entityID = "https://sp.example.com/saml/metadata"
	sessions := sessionsByCookie{}
	idp, router := newIdPRouter(t, sessions)
	organizationID := dbtest.Organization(t)
	member := dbtest.User(t, organizationID)
	cookie := "session-" + uuid.NewString()
	sessions[cookie] = member.ID
	sp := registerSP(t, ctx, idp, organizationID, entityID, "https://sp.example.com/acs")

	request := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_post-1" AssertionConsumerServiceURL="` + sp.ACSURL + `">` +
		`<saml:Issuer>` + entityID + `</saml:Issuer></samlp:AuthnRequest>`
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(request))}, "RelayState": {"state-1"}}
	prefix := "/saml/idp/" + organizationID.String() + "/sso"
	req := httptest.NewRequest(http.MethodPost, "https://other.example"+prefix, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST without a session = %d %s, want 302", rec.Code, rec.Body.String())
	}
	login, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	returnTo := login.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, testPublicBase+prefix+"?") {
		t.Fatalf("return_to %q, want this organization's SSO endpoint", returnTo)
	}

	back := idpGet(t, router, strings.TrimPrefix(returnTo, testPublicBase), cookie)
	if acs, _ := postedTo(t, back); acs != sp.ACSURL {
		t.Errorf("resumed SSO posted to %q, want %q", acs, sp.ACSURL)
	}
	if !strings.Contains(back.Body.String(), `name="RelayState" value="state-1"`) {
		t.Errorf("resumed SSO lost the RelayState: %s", back.Body.String())
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(samlResponseRe.FindStringSubmatch(back.Body.String())[1]))
	if err != nil || !strings.Contains(string(xml), `InResponseTo="_post-1"`) {
		t.Errorf("resumed SSO doesn't answer the request: %s (%v)", xml, err)
	}
}

// TestSAMLIdPAppliesTheOrganizationsAddressRulesAndSecondFactor checks that the
// IdP signs an assertion only as OIDC authorize would: from an address the
// organization's rules allow (a refused one is refused and recorded), and for a
// session that met the second factor the organization requires. One that
// didn't is sent to sign in again for this request, and refused when that
// fresh sign-in still hasn't.
func TestSAMLIdPAppliesTheOrganizationsAddressRulesAndSecondFactor(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(mfa.NewService(pool, "Qeet", notifier.LogSender{}))
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(pool, keyPEM, certPEM, "https://login.id.qeet.in", authSvc)
	if err != nil {
		t.Fatal(err)
	}
	idp.SetSignInRules(ipallow.NewService(pool), authSvc)
	router := chi.NewRouter()
	(&Handler{Service: &Service{}, IdP: idp, PublicBaseURL: testPublicBase}).MountPublic(router)
	organization := dbtest.Organization(t)
	member := dbtest.User(t, organization, organization)
	sp := registerSP(t, ctx, idp, organization, "https://sp.example.test/metadata", "https://sp.example.test/acs")
	sso := "/saml/idp/" + organization.String() + "/sso?" + authnRequestTo(sp.EntityID, "_req-1", "")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`WITH rule AS (INSERT INTO organization.ip_rules (organization_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO organization.ip_rules_config (organization_id, enabled) VALUES ($1, TRUE)`, organization)
	session := func() string {
		t.Helper()
		raw, err := authSvc.CreateLoginSession(ctx, member.ID, "192.0.2.10", "test")
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	const office, elsewhere = "192.0.2.10:4000", "198.51.100.7:4000"
	get := func(path, cookie, from string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "https://other.example"+path, nil)
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
		req.RemoteAddr = from
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	cookie := session()
	if rec := get(sso, cookie, elsewhere); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeAuthAddressNotAllowed) {
		t.Errorf("SSO from an address the rules refuse: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeAuthAddressNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.address_refused' AND metadata->>'path' = 'saml_idp'`, organization); n != 1 {
		t.Errorf("the refused address was recorded %d times, want once", n)
	}
	if acs, _ := postedTo(t, get(sso, cookie, office)); acs != sp.ACSURL {
		t.Fatalf("SSO from the office posted to %q, want %q", acs, sp.ACSURL)
	}

	exec(`INSERT INTO organization.security_policies (organization_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since) VALUES ($1, 'required', 0, NOW())`, organization)
	rec := get(sso, cookie, office)
	to, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || to.Host != "login.id.qeet.in" || to.Path != "/sign-in" || to.Query().Get("prompt") != "login" {
		t.Fatalf("SSO for a session short of the required factor: %d to %s, want sent to sign in again", rec.Code, rec.Header().Get("Location"))
	}
	back, err := url.Parse(to.Query().Get("return_to"))
	if err != nil || back.Query().Get("SAMLRequest") == "" || back.Query().Get("login_after") == "" {
		t.Fatalf("return_to %q, want this request, marked", to.Query().Get("return_to"))
	}
	fresh := session()
	if rec := get(back.RequestURI(), fresh, office); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeMFAEnrollmentRequired) {
		t.Errorf("SSO after a fresh sign-in still short of the factor: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeMFAEnrollmentRequired)
	}
	exec(`UPDATE auth.login_sessions SET second_factor = 'mfa' WHERE user_id = $1`, member.ID)
	if acs, _ := postedTo(t, get(sso, cookie, office)); acs != sp.ACSURL {
		t.Errorf("SSO for a session that met the factor posted to %q, want %q", acs, sp.ACSURL)
	}
}

// TestIdPSSOAnswers pins what the IdP's SSO endpoint answers at each step and
// what it records: a refusal of someone signed in as saml.idp_assertion_refused
// with its reason, an issued assertion as saml.idp_assertion_issued with the
// service provider's last sign-in, and nothing for a request it can't read.
func TestIdPSSOAnswers(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	organization := dbtest.Organization(t)
	member := dbtest.User(t, organization, organization)
	cookie := s.signIn(member.ID)
	sp := registerSP(t, ctx, s.idp, organization, "https://sp-"+uuid.NewString()+".example.test/metadata", "https://sp.example.test/acs")
	base := "/saml/idp/" + organization.String() + "/sso"
	recorded := func(action, reason string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3
			AND actor_user_id = $4 AND actor_type = 'user' AND coalesce(metadata->>'reason', '') = $5 AND metadata->>'sp_entity_id' = $6`,
			organization, action, sp.ID, member.ID, reason, sp.EntityID)
	}
	for _, tc := range []struct {
		name, query, cookie, want string
	}{
		{"no request", "", cookie, CodeRequestParamMissing},
		{"an unreadable request", "SAMLRequest=not-a-request", cookie, CodeAuthnRequestInvalid},
		{"an unknown service provider", authnRequestTo("https://unknown.example.test", "_r-1", ""), cookie, errs.CodeNotFound},
		{"another ACS", authnRequestTo(sp.EntityID, "_r-2", "https://evil.example.test/acs"), cookie, CodeACSMismatch},
	} {
		if rec := idpGet(t, s.router, base+"?"+tc.query, tc.cookie); !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want %s", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	rec := idpGet(t, s.router, base+"?"+authnRequestTo(sp.EntityID, "_r-3", ""), "")
	if location := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(location, "https://login.id.qeet.in/sign-in?return_to=") {
		t.Errorf("not signed in: %d %s, want the hosted sign-in", rec.Code, location)
	}

	acs, _ := postedTo(t, idpGet(t, s.router, base+"?"+authnRequestTo(sp.EntityID, "_r-4", sp.ACSURL), cookie))
	if acs != sp.ACSURL || recorded("saml.idp_assertion_issued", "") != 1 {
		t.Errorf("issued to %s with %d issued rows, want %s and 1", acs, recorded("saml.idp_assertion_issued", ""), sp.ACSURL)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_service_providers WHERE id = $1 AND last_login_at IS NOT NULL`, sp.ID); n != 1 {
		t.Error("the service provider's last sign-in was not recorded")
	}

	setSPStatus(t, ctx, s.idp, sp, "draft")
	if rec := idpGet(t, s.router, base+"?sp="+sp.ID.String(), cookie); !strings.Contains(rec.Body.String(), CodeServiceProviderDraft) {
		t.Errorf("a draft: %d %s, want %s", rec.Code, rec.Body.String(), CodeServiceProviderDraft)
	}
	if recorded("saml.idp_assertion_refused", "draft") != 1 {
		t.Error("the refusal of a draft was not recorded")
	}
	setSPStatus(t, ctx, s.idp, sp, "disabled")
	if rec := idpGet(t, s.router, base+"?sp="+sp.ID.String(), cookie); !strings.Contains(rec.Body.String(), CodeServiceProviderDisabled) {
		t.Errorf("disabled: %d %s, want %s", rec.Code, rec.Body.String(), CodeServiceProviderDisabled)
	}
}
