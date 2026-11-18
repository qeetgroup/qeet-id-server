//go:build integration

package oidc

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestDiscoveryNamesTheIssuerTokensCarry checks that both metadata documents
// name as issuer the iss of the authorization response and of the ID token,
// which relying parties compare exactly.
func TestDiscoveryNamesTheIssuerTokensCarry(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, p.svc, organization)
	cookie, _ := p.signIn(t, person.ID)
	if err := p.svc.GrantConsent(ctx, person.ID, client.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	target, verifier := authorizeURL(t, client.ClientID)
	_, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	issued, err := p.svc.ExchangeCode(ctx, client.ClientID, secret, q.Get("code"), testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("redeem the code: %v", err)
	}
	id, err := p.svc.issuer.VerifySigned(issued.IDToken)
	if err != nil {
		t.Fatalf("verify the ID token: %v", err)
	}

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		var doc map[string]any
		dbtest.Decode(t, browse(t, p.public, http.MethodGet, path, nil, nil), &doc)
		if doc["issuer"] != q.Get("iss") || doc["issuer"] != id["iss"] {
			t.Errorf("%s issuer %v; the authorization response says %q and the ID token %v", path, doc["issuer"], q.Get("iss"), id["iss"])
		}
	}
}
