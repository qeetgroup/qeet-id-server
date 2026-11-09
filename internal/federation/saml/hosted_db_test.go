//go:build integration

package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAHostedSignInReturnsToTheHostedLogin checks that a sign-in the hosted login started comes
// back to the hosted login's sign-in page with its return address and the one-time code in the
// fragment, and that the code buys the hosted login session once, not a token pair.
func TestAHostedSignInReturnsToTheHostedLogin(t *testing.T) {
	sp := newSPSide(t)
	const accounts = "https://accounts.example.test"
	sp.handler.Service.SetHostedLogin(accounts, testPublicBase)
	idp := newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, tenant), tenant, tenant)
	verify(t, member.ID)
	returnTo := testPublicBase + "/oauth/authorize?client_id=portal&state=s1"

	rec := sp.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet,
		"/saml/login/"+conn.ID.String()+"?return_to="+url.QueryEscape(returnTo), nil))
	location, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || location == nil {
		t.Fatalf("login with return_to: %d %s", rec.Code, rec.Body.String())
	}
	ar, err := decodeAuthnRequest(location.Query().Get("SAMLRequest"), http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	answered := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: ar.ID, nameID: "okta|asha", email: member.Email}))
	want := accounts + "/sign-in?" + url.Values{"return_to": {returnTo}}.Encode() + "#saml_code="
	got := answered.Header().Get("Location")
	if answered.Code != http.StatusFound || !strings.HasPrefix(got, want) || len(got) == len(want) {
		t.Fatalf("ACS: %d %s, want the hosted login's sign-in with the code", answered.Code, got)
	}
	code := strings.TrimPrefix(got, want)

	session := dbtest.Do(t, sp.public, http.MethodPost, "/saml/session", map[string]string{"code": code})
	var signedIn struct {
		UserID string `json:"user_id"`
	}
	dbtest.Decode(t, session, &signedIn)
	if session.Code != http.StatusOK || signedIn.UserID != member.ID.String() || !strings.Contains(session.Header().Get("Set-Cookie"), "qe_ls=") {
		t.Fatalf("session: %d %s %q, want the hosted login cookie for the member", session.Code, session.Body.String(), session.Header().Get("Set-Cookie"))
	}
	if again := dbtest.Do(t, sp.public, http.MethodPost, "/saml/session", map[string]string{"code": code}); !strings.Contains(again.Body.String(), errs.CodeSAMLLoginCodeUsed) {
		t.Errorf("the code again: %d %s, want %s", again.Code, again.Body.String(), errs.CodeSAMLLoginCodeUsed)
	}
}
