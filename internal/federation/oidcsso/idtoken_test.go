package oidcsso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// verifier returns a provider client for p's keys, on a clock the test moves,
// and the rules of a sign-in that sent nonce.
func verifier(t *testing.T, p *fakeIdP, nonce string) (*providerClient, *time.Time, idTokenRules) {
	t.Helper()
	c := newProviderClient(egress.DevelopmentPolicy())
	now := time.Now()
	c.now = func() time.Time { return now }
	return c, &now, idTokenRules{issuer: p.URL, clientID: testClientID, nonceHash: codes.Hash(nonce)}
}

// TestIDTokenChecks checks that an ID token signs someone in only when the
// provider's published key signed it with an asymmetric algorithm, and it is
// from the connection's issuer, for this client, current, and carries the
// nonce the sign-in sent.
func TestIDTokenChecks(t *testing.T) {
	p := newFakeIdP(t)
	c, _, rules := verifier(t, p, "nonce-1")
	jwks := p.URL + "/jwks"
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	valid := func() jwt.MapClaims { return p.claimsFor("nonce-1", "user-1", "asha@example.test") }
	with := func(change func(jwt.MapClaims)) jwt.MapClaims {
		claims := valid()
		change(claims)
		return claims
	}
	hmac := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token.Header["kid"] = "key-1"
		raw, err := token.SignedString([]byte(testClientSecret))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	unsigned := func(claims jwt.MapClaims) string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	if claims, err := c.verifyIDToken(context.Background(), p.sign(t, valid(), nil, ""), jwks, rules); err != nil || claims["sub"] != "user-1" {
		t.Fatalf("a correct token: %v, %v", claims, err)
	}
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, with(func(c jwt.MapClaims) {
		c["aud"] = []string{"other-client", testClientID}
		c["azp"] = testClientID
	}), nil, ""), jwks, rules); err != nil {
		t.Errorf("a token for several audiences naming this client as its party: %v", err)
	}

	for name, raw := range map[string]string{
		"signed by another key under the provider's kid": p.sign(t, valid(), stranger, "key-1"),
		"signed with the client secret (HS256)":          hmac(valid()),
		"unsigned (alg none)":                            unsigned(valid()),
		"from another issuer":                            p.sign(t, with(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.test" }), nil, ""),
		"for another client":                             p.sign(t, with(func(c jwt.MapClaims) { c["aud"] = "other-client" }), nil, ""),
		"for several audiences without azp":              p.sign(t, with(func(c jwt.MapClaims) { c["aud"] = []string{"other-client", testClientID} }), nil, ""),
		"authorized for another party":                   p.sign(t, with(func(c jwt.MapClaims) { c["azp"] = "other-client" }), nil, ""),
		"with another sign-in's nonce":                   p.sign(t, with(func(c jwt.MapClaims) { c["nonce"] = "nonce-2" }), nil, ""),
		"with no nonce":                                  p.sign(t, with(func(c jwt.MapClaims) { delete(c, "nonce") }), nil, ""),
		"expired beyond the skew":                        p.sign(t, with(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-2 * clockSkew).Unix() }), nil, ""),
		"with no expiry":                                 p.sign(t, with(func(c jwt.MapClaims) { delete(c, "exp") }), nil, ""),
		"issued in the future":                           p.sign(t, with(func(c jwt.MapClaims) { c["iat"] = time.Now().Add(2 * clockSkew).Unix() }), nil, ""),
		"with no issue time":                             p.sign(t, with(func(c jwt.MapClaims) { delete(c, "iat") }), nil, ""),
		"not yet valid":                                  p.sign(t, with(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(2 * clockSkew).Unix() }), nil, ""),
		"with no subject":                                p.sign(t, with(func(c jwt.MapClaims) { delete(c, "sub") }), nil, ""),
		"naming a key the provider doesn't publish":      p.sign(t, valid(), stranger, "key-9"),
		"not a token":                                    "not.a.token",
	} {
		if _, err := c.verifyIDToken(context.Background(), raw, jwks, rules); err == nil {
			t.Errorf("a token %s was accepted", name)
		}
	}
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, valid(), nil, ""), jwks, idTokenRules{issuer: p.URL, clientID: testClientID}); err == nil {
		t.Error("a token was accepted by a sign-in that recorded no nonce")
	}
}

// TestIDTokenKeysRotate checks that a token under a key not yet seen fetches
// the provider's keys again, but not more than once in keysMinRefresh, and
// that EC keys verify too.
func TestIDTokenKeysRotate(t *testing.T) {
	p := newFakeIdP(t)
	c, now, rules := verifier(t, p, "nonce-1")
	jwks := p.URL + "/jwks"
	claims := func() jwt.MapClaims { return p.claimsFor("nonce-1", "user-1", "asha@example.test") }
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, claims(), nil, ""), jwks, rules); err != nil {
		t.Fatal(err)
	}
	p.rotate(t, "key-2")
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, claims(), nil, ""), jwks, rules); err == nil || p.fetches() != 1 {
		t.Errorf("a new key straight after a fetch: %v after %d fetches; want refused without fetching again", err, p.fetches())
	}
	*now = now.Add(keysMinRefresh + time.Second)
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, claims(), nil, ""), jwks, rules); err != nil || p.fetches() != 2 {
		t.Errorf("a rotated key: %v after %d fetches; want accepted after one more", err, p.fetches())
	}
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, claims(), nil, ""), jwks, rules); err != nil || p.fetches() != 2 {
		t.Errorf("the rotated key again: %v after %d fetches; want it cached", err, p.fetches())
	}

	ec := newECKey(t)
	p.mu.Lock()
	p.published = append(p.published, ecJWK("ec-1", &ec.PublicKey))
	p.mu.Unlock()
	*now = now.Add(keysMinRefresh + time.Second)
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, claims(), ec, "ec-1"), jwks, rules); err != nil {
		t.Errorf("a token signed with a published EC key: %v", err)
	}
	if _, err := c.verifyIDToken(context.Background(), p.sign(t, claims(), newECKey(t), "ec-1"), jwks, rules); err == nil {
		t.Error("a token signed by another EC key under the published kid was accepted")
	}
}

// TestIDTokenTenants checks that a provider serving many tenants signs in only
// the tenants the connection lists, each under its own issuer.
func TestIDTokenTenants(t *testing.T) {
	p := newFakeIdP(t)
	c, _, rules := verifier(t, p, "nonce-1")
	jwks := p.URL + "/jwks"
	const mine, theirs = "6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11", "0e3b5f11-1111-4c2a-8f2e-7a1d3c9b2e22"
	rules.issuerTemplate = "https://login.example.test/{tenantid}/v2.0"
	rules.tenantIDs = []string{mine}
	token := func(iss, tid string) string {
		claims := p.claimsFor("nonce-1", "user-1", "asha@example.test")
		claims["iss"] = iss
		if tid != "" {
			claims["tid"] = tid
		}
		return p.sign(t, claims, nil, "")
	}
	if _, err := c.verifyIDToken(context.Background(), token("https://login.example.test/"+mine+"/v2.0", mine), jwks, rules); err != nil {
		t.Errorf("a token from a listed tenant: %v", err)
	}
	for name, raw := range map[string]string{
		"from a tenant not listed":                    token("https://login.example.test/"+theirs+"/v2.0", theirs),
		"naming a listed tenant under another issuer": token("https://login.example.test/"+theirs+"/v2.0", mine),
		"naming no tenant":                            token("https://login.example.test/"+mine+"/v2.0", ""),
		"from the template itself":                    token(rules.issuerTemplate, mine),
	} {
		if _, err := c.verifyIDToken(context.Background(), raw, jwks, rules); err == nil {
			t.Errorf("a token %s was accepted", name)
		}
	}

	conn := &Connection{Issuer: "https://login.example.test/organizations/v2.0"}
	if _, err := rulesFor(conn, discovery{Issuer: rules.issuerTemplate}); err == nil {
		t.Error("a multi-tenant provider was accepted for a connection listing no tenants")
	}
	conn.AllowedIdPTenantIDs = []string{mine}
	if got, err := rulesFor(conn, discovery{Issuer: rules.issuerTemplate}); err != nil || got.issuerTemplate != rules.issuerTemplate {
		t.Errorf("a multi-tenant provider for a connection listing its tenants: %+v, %v", got, err)
	}
	if _, err := rulesFor(&Connection{Issuer: "https://idp.example.test"}, discovery{Issuer: "https://other.example.test"}); err == nil {
		t.Error("a discovery document naming another issuer was accepted")
	}
}

// TestProfileOf checks which claims a sign-in reads, and that email_verified
// speaks only for the email claim.
func TestProfileOf(t *testing.T) {
	conn := &Connection{ClaimMapping: ClaimMapping{Email: "email", Name: "name", GivenName: "given_name", FamilyName: "family_name", Groups: "groups"}}
	p := conn.profileOf(jwt.MapClaims{
		"iss": "https://idp.example.test", "sub": "u-1", "email": " Asha@Example.Test ", "email_verified": "false",
		"given_name": "Asha", "family_name": "Rao", "groups": []any{"eng", 7, "ops"},
	})
	if p.subject != "https://idp.example.test#u-1" || p.email != "asha@example.test" || p.name != "Asha Rao" ||
		p.verified == nil || *p.verified || len(p.groups) != 2 {
		t.Errorf("profile %+v", p)
	}
	if p := conn.profileOf(jwt.MapClaims{"email": "asha@example.test"}); p.verified != nil {
		t.Errorf("a token that doesn't say: verified %v, want unknown", *p.verified)
	}
	conn.ClaimMapping.Email = "upn"
	if p := conn.profileOf(jwt.MapClaims{"upn": "asha@example.test", "email_verified": false}); p.email != "asha@example.test" || p.verified != nil {
		t.Errorf("email read from upn: %+v; want email_verified ignored", p)
	}
}

// TestConnectionInputChecks checks the settings a connection is refused with.
func TestConnectionInputChecks(t *testing.T) {
	policy := egress.PublicPolicy()
	base := func() CreateInput {
		return CreateInput{Name: "Entra", Issuer: "https://login.microsoftonline.com/6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11/v2.0", ClientID: "id", ClientSecret: "secret"}
	}
	in := base()
	if err := in.check(policy); err != nil || len(in.Scopes) != 3 || in.Scopes[0] != "openid" {
		t.Fatalf("a complete connection: %v, scopes %v", err, in.Scopes)
	}
	empty := ""
	for code, change := range map[string]func(*CreateInput){
		errs.CodeOIDCSSOFieldsRequired: func(in *CreateInput) { in.ClientSecret = "" },
		errs.CodeOIDCSSOIssuerInvalid:  func(in *CreateInput) { in.Issuer = "http://idp.example.test" },
		errs.CodeOIDCSSODiscoveryURLInvalid: func(in *CreateInput) {
			in.DiscoveryURL = "https://idp.example.test/.well-known/openid-configuration#x"
		},
		errs.CodeOIDCSSOScopesInvalid:     func(in *CreateInput) { in.Scopes = []string{"email profile"} },
		errs.CodeOIDCSSOTenantIDsInvalid:  func(in *CreateInput) { in.AllowedIdPTenantIDs = []string{"contoso"} },
		errs.CodeOIDCSSOTenantIDsRequired: func(in *CreateInput) { in.Issuer = "https://login.microsoftonline.com/common/v2.0" },
		errs.CodeOIDCSSOClaimInvalid:      func(in *CreateInput) { in.ClaimMapping = &ClaimMappingInput{Email: &empty} },
		errs.CodeOIDCSSOStatusInvalid:     func(in *CreateInput) { in.Status = "enabled" },
	} {
		in := base()
		change(&in)
		if err := in.check(policy); !errors.Is(err, errs.New(code, "")) {
			t.Errorf("%s: %v", code, err)
		}
	}
	in = base()
	in.Issuer = "https://login.microsoftonline.com/organizations/v2.0"
	in.AllowedIdPTenantIDs = []string{"6F1C7A52-8C1E-4A43-9A8E-2D6F0B0F5F11", "6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11"}
	in.Scopes = []string{"email", "offline_access", "email"}
	if err := in.check(policy); err != nil || len(in.AllowedIdPTenantIDs) != 1 || len(in.Scopes) != 3 {
		t.Errorf("a multi-tenant issuer listing its tenant: %v, %v, %v", err, in.AllowedIdPTenantIDs, in.Scopes)
	}
}
