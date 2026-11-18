//go:build integration

package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const testReturnURL = "https://login.example.test/enterprise-setup" // where a test's answer returns the browser

// draftConnection has organization's admin create a draft connection to idp over HTTP.
func (s *spSide) draftConnection(t *testing.T, organization uuid.UUID, idp *upstreamIdP) Connection {
	t.Helper()
	rec := dbtest.Do(t, s.asAdmin(t, organization), http.MethodPost, "/organizations/"+organization.String()+"/saml", map[string]any{
		"name": "Okta", "idp_entity_id": idp.entityID, "idp_sso_url": upstreamSSO, "idp_certificate": idp.certPEM,
		"email_attribute": "email", "name_attribute": "name",
	})
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.Status != "draft" {
		t.Fatalf("create a draft connection: %d %s", rec.Code, rec.Body.String())
	}
	return conn
}

// beginTest starts a test sign-in of organization's connID in the browser and
// returns it with the ID of the AuthnRequest sent to the IdP.
func (s *spSide) beginTest(t *testing.T, organization, connID uuid.UUID) (*TestSignIn, string) {
	t.Helper()
	test, err := s.tryTest(t, organization, connID)
	if err != nil {
		t.Fatalf("begin a test sign-in: %v", err)
	}
	location, err := url.Parse(test.RedirectURL)
	if err != nil || !strings.HasPrefix(test.RedirectURL, upstreamSSO+"?") || test.Status != testPending {
		t.Fatalf("test %+v; want a pending test sending the browser to the IdP", test)
	}
	ar, err := decodeAuthnRequest(location.Query().Get("SAMLRequest"), http.MethodGet)
	if err != nil {
		t.Fatalf("decode the AuthnRequest: %v", err)
	}
	if ar.Issuer != spEntityID(testPublicBase, connID) || ar.AssertionConsumerServiceURL != acsURL(testPublicBase, connID) {
		t.Fatalf("AuthnRequest %+v; want this connection's entity and ACS", ar)
	}
	return test, ar.ID
}

// tryTest begins a test sign-in of organization's connID in the browser, as the
// admin portal does.
func (s *spSide) tryTest(t *testing.T, organization, connID uuid.UUID) (*TestSignIn, error) {
	t.Helper()
	ctx := dbtest.Context(t)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/admin-portal/saml/"+connID.String()+"/test-sign-ins", nil)
	for _, c := range s.browser {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	test, err := s.handler.BeginTestSignIn(rec, req, organization, connID, testReturnURL, audit.Actor{Type: "admin_portal"})
	if err != nil {
		return nil, err
	}
	s.keep(rec)
	return test, nil
}

// TestSAMLTestSignIn checks that a test sign-in runs the real round trip
// through a draft connection's IdP and reports what it asserted, creating no
// account, link, code or session, and that its answer is accepted only from
// the browser that began it, once, and never as a sign-in.
func TestSAMLTestSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.draftConnection(t, organization, idp)
	tester := dbtest.Unique("tester") + "@" + dbtest.Domain(t, organization)

	test, requestID := sp.beginTest(t, organization, conn.ID)
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.saml_authn_requests WHERE request_id = $1`, requestID); n != 0 {
		t.Error("a test's AuthnRequest is open to sign-in")
	}
	response := idp.respond(t, conn.ID, answer{inResponseTo: requestID, nameID: "okta|tester", email: strings.ToUpper(tester)})
	rec := sp.post(t, conn.ID, response)
	back := testReturnURL + "#saml_test=" + test.ID.String() + "&saml_connection=" + conn.ID.String()
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != back {
		t.Fatalf("ACS: %d %s %s; want the portal page with the test", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	got, err := sp.handler.Service.TestSignIn(ctx, test.ID, conn.ID, organization)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != testSucceeded || got.Email != tester || got.Name != "Asha Rao" || got.NameID != "okta|tester" ||
		!got.EmailDomainVerified || got.CompletedAt == nil || got.ErrorCode != "" {
		t.Errorf("test %+v; want it succeeded, with what the IdP asserted", got)
	}
	if len(got.Attributes) != 2 || got.Attributes[0].Name != "email" || len(got.Attributes[0].Values) != 1 ||
		got.Attributes[0].Values[0] != strings.ToUpper(tester) || got.Attributes[1].Name != "name" {
		t.Errorf("attributes %+v; want the email and name the IdP sent", got.Attributes)
	}
	for what, n := range map[string]int{
		"accounts":          dbtest.Count(t, `SELECT count(*) FROM account.users WHERE lower(email) = $1`, tester),
		"linked identities": dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE connection_id = $1`, conn.ID),
		"login codes":       dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE organization_id = $1`, organization),
		"sessions":          dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE organization_id = $1`, organization),
		"sign-ins recorded": dbtest.Count(t, `SELECT count(*) FROM organization.saml_connections WHERE id = $1 AND last_login_at IS NOT NULL`, conn.ID),
	} {
		if n != 0 {
			t.Errorf("the test left %d %s, want none", n, what)
		}
	}
	if rec := sp.post(t, conn.ID, response); !strings.Contains(rec.Body.String(), CodeOtherBrowser) {
		t.Errorf("a test's answer posted again: %d %s, want %s", rec.Code, rec.Body.String(), CodeOtherBrowser)
	}

	// Another browser can't complete a test it didn't begin.
	pending, pendingRequest := sp.beginTest(t, organization, conn.ID)
	mine := sp.browser
	sp.browser = nil
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: pendingRequest, email: tester})); !strings.Contains(rec.Body.String(), CodeOtherBrowser) {
		t.Errorf("a test answered in another browser: %d %s, want %s", rec.Code, rec.Body.String(), CodeOtherBrowser)
	}
	sp.browser = mine
	if got, err := sp.handler.Service.TestSignIn(ctx, pending.ID, conn.ID, organization); err != nil || got.Status != testPending {
		t.Errorf("a test answered in another browser: %+v %v, want it still pending", got, err)
	}

	// What a sign-in would refuse, the test reports.
	other := dbtest.Organization(t)
	for name, c := range map[string]struct {
		a        answer
		code     string
		asserted bool
	}{
		"an answer for another audience":              {answer{email: tester, audience: "https://other-sp.example.test"}, CodeAssertionConditions, true},
		"an unsigned answer":                          {answer{email: tester, unsigned: true}, errs.CodeSAMLAssertionInvalid, false},
		"an answer from another issuer":               {answer{email: tester, issuer: "https://impostor.example.test"}, errs.CodeSAMLAssertionInvalid, false},
		"an address on a domain nobody verified":      {answer{email: dbtest.Unique("x") + "@example.test"}, CodeEmailDomainUnverified, true},
		"an address on another organization's domain": {answer{email: "x@" + dbtest.Domain(t, other)}, CodeEmailDomainUnverified, true},
	} {
		test, requestID := sp.beginTest(t, organization, conn.ID)
		c.a.inResponseTo = requestID
		if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, c.a)); rec.Code != http.StatusFound {
			t.Errorf("%s: ACS %d %s, want the portal page", name, rec.Code, rec.Body.String())
			continue
		}
		got, err := sp.handler.Service.TestSignIn(ctx, test.ID, conn.ID, organization)
		if err != nil || got.Status != testFailed || got.ErrorCode != c.code || got.ErrorMessage == "" || (got.NameID != "") != c.asserted {
			t.Errorf("%s: %+v %v; want it failed with %s", name, got, err, c.code)
		}
	}

	// A test no answer reached in time has expired, and an answer can't revive it.
	late, lateRequest := sp.beginTest(t, organization, conn.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.saml_test_sign_ins SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, late.ID); err != nil {
		t.Fatal(err)
	}
	sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: lateRequest, email: tester}))
	if got, err := sp.handler.Service.TestSignIn(ctx, late.ID, conn.ID, organization); err != nil || got.Status != testExpired || got.CompletedAt != nil {
		t.Errorf("a late test: %+v %v, want it expired", got, err)
	}

	// Another organization can neither read the test nor test its connection.
	if _, err := sp.handler.Service.TestSignIn(ctx, test.ID, conn.ID, other); !errors.Is(err, ErrTestSignInNotFound) {
		t.Errorf("another organization reads the test: %v, want %s", err, CodeTestSignInNotFound)
	}
	theirs := sp.draftConnection(t, other, idp)
	if _, err := sp.tryTest(t, organization, theirs.ID); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("testing another organization's connection: %v, want not found", err)
	}

	// Purged, and the connection on, the test's answer still signs nobody in.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.saml_test_sign_ins SET created_at = NOW() - INTERVAL '2 hours' WHERE id = $1`, test.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := PurgeTestSignIns(ctx, dbtest.Pool(t), TestSignInRetention); err != nil || n != 1 {
		t.Fatalf("purge: %d %v, want the one old test", n, err)
	}
	if _, err := sp.handler.Service.TestSignIn(ctx, test.ID, conn.ID, organization); !errors.Is(err, ErrTestSignInNotFound) {
		t.Errorf("a purged test: %v, want %s", err, CodeTestSignInNotFound)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.saml_connections SET status = 'active' WHERE id = $1 AND organization_id = $2`, conn.ID, organization); err != nil {
		t.Fatal(err)
	}
	if rec := sp.post(t, conn.ID, response); rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), CodeReplayDetected) {
		t.Errorf("a test's answer as a sign-in: %d %s, want %s", rec.Code, rec.Body.String(), CodeReplayDetected)
	}
}
