//go:build integration

package oidcsso

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAHostedSignInTheProviderRefusesReturnsToTheHostedLogin checks that a sign-in the hosted
// login began, which the provider then refuses, goes back to the hosted login's sign-in page with
// a generic error and its return address, and is still recorded for the organisation.
func TestAHostedSignInTheProviderRefusesReturnsToTheHostedLogin(t *testing.T) {
	s := newRP(t)
	const accounts = "https://accounts.example.test"
	s.svc.SetHostedLogin(accounts, testPublicBase)
	idp := newFakeIdP(t)
	tenant := dbtest.Tenant(t)
	conn := s.connect(t, tenant, idp, nil)
	returnTo := testPublicBase + "/oauth/authorize?client_id=portal&state=s1"

	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet,
		"/oidc-connections/"+conn.ID.String()+"/login?return_to="+url.QueryEscape(returnTo), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login with return_to: %d %s", rec.Code, rec.Body.String())
	}
	answered := s.callback(t, conn.ID, rec.Header().Get("Location"), "", url.Values{"error": {"access_denied"}})
	want := accounts + "/sign-in?" + url.Values{"error": {"sso"}, "return_to": {returnTo}}.Encode()
	if got := answered.Header().Get("Location"); answered.Code != http.StatusFound || got != want {
		t.Fatalf("callback: %d %s %s, want the hosted login's sign-in with the error", answered.Code, got, answered.Body.String())
	}
	if n := failures(t, tenant, errs.CodeOIDCSSOProviderRefused); n != 1 {
		t.Errorf("%d refusals recorded, want 1", n)
	}
}
