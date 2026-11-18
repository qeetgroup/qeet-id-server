package oidcrp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp/oidcrptest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	testClientID     = "qeet-client"
	testClientSecret = "qeet-client-secret" // #nosec G101 -- a test fixture
)

// verifier returns a client for p's keys, on a clock the test moves, and the
// rules of a sign-in that sent nonce.
func verifier(t *testing.T, p *oidcrptest.Provider, nonce string) (*Client, *time.Time, Rules) {
	t.Helper()
	c := New(egress.DevelopmentPolicy())
	now := time.Now()
	c.now = func() time.Time { return now }
	return c, &now, Rules{Issuer: p.URL, ClientID: testClientID, NonceHash: codes.Hash(nonce)}
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestIDTokenChecks checks that an ID token signs someone in only when the
// provider's published key it names signed it with an asymmetric algorithm,
// and it is from the expected issuer, for this client, current, and carries
// the nonce the sign-in sent.
func TestIDTokenChecks(t *testing.T) {
	p := oidcrptest.New(t, testClientID, testClientSecret)
	c, _, rules := verifier(t, p, "nonce-1")
	jwks := p.JWKSURL()
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	valid := func() jwt.MapClaims { return p.Claims("nonce-1", "user-1", "asha@example.test") }
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
	noKid := func(claims jwt.MapClaims) string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(stranger)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	if claims, err := c.VerifyIDToken(context.Background(), p.Sign(t, valid(), nil, ""), jwks, rules); err != nil || claims["sub"] != "user-1" {
		t.Fatalf("a correct token: %v, %v", claims, err)
	}
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, with(func(c jwt.MapClaims) {
		c["aud"] = []string{"other-client", testClientID}
		c["azp"] = testClientID
	}), nil, ""), jwks, rules); err != nil {
		t.Errorf("a token for several audiences naming this client as its party: %v", err)
	}

	for name, raw := range map[string]string{
		"signed by another key under the provider's kid": p.Sign(t, valid(), stranger, "key-1"),
		"signed with the client secret (HS256)":          hmac(valid()),
		"unsigned (alg none)":                            unsigned(valid()),
		"naming no key":                                  noKid(valid()),
		"from another issuer":                            p.Sign(t, with(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.test" }), nil, ""),
		"for another client":                             p.Sign(t, with(func(c jwt.MapClaims) { c["aud"] = "other-client" }), nil, ""),
		"for several audiences without azp":              p.Sign(t, with(func(c jwt.MapClaims) { c["aud"] = []string{"other-client", testClientID} }), nil, ""),
		"authorized for another party":                   p.Sign(t, with(func(c jwt.MapClaims) { c["azp"] = "other-client" }), nil, ""),
		"with another sign-in's nonce":                   p.Sign(t, with(func(c jwt.MapClaims) { c["nonce"] = "nonce-2" }), nil, ""),
		"with no nonce":                                  p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "nonce") }), nil, ""),
		"expired beyond the skew":                        p.Sign(t, with(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-2 * clockSkew).Unix() }), nil, ""),
		"with no expiry":                                 p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "exp") }), nil, ""),
		"issued in the future":                           p.Sign(t, with(func(c jwt.MapClaims) { c["iat"] = time.Now().Add(2 * clockSkew).Unix() }), nil, ""),
		"with no issue time":                             p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "iat") }), nil, ""),
		"not yet valid":                                  p.Sign(t, with(func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(2 * clockSkew).Unix() }), nil, ""),
		"with no subject":                                p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "sub") }), nil, ""),
		"with an overlong subject":                       p.Sign(t, with(func(c jwt.MapClaims) { c["sub"] = strings.Repeat("s", maxSubjectLen+1) }), nil, ""),
		"naming a key the provider doesn't publish":      p.Sign(t, valid(), stranger, "key-9"),
		"not a token":                                    "not.a.token",
	} {
		if _, err := c.VerifyIDToken(context.Background(), raw, jwks, rules); err == nil {
			t.Errorf("a token %s was accepted", name)
		}
	}
	for name, r := range map[string]Rules{
		"a sign-in that recorded no nonce": {Issuer: p.URL, ClientID: testClientID},
		"rules naming no issuer":           {ClientID: testClientID, NonceHash: rules.NonceHash},
		"rules naming no client":           {Issuer: p.URL, NonceHash: rules.NonceHash},
		"rules allowing only ES256":        {Issuer: p.URL, ClientID: testClientID, NonceHash: rules.NonceHash, Algorithms: []string{"ES256"}},
		"rules allowing only HS256":        {Issuer: p.URL, ClientID: testClientID, NonceHash: rules.NonceHash, Algorithms: []string{"HS256"}},
	} {
		if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, valid(), nil, ""), jwks, r); err == nil {
			t.Errorf("a token was accepted by %s", name)
		}
	}
}

// TestIDTokenKeysRotate checks that a token under a key not yet seen fetches
// the provider's keys again, but not more than once in keysMinRefresh, and
// that EC keys verify too.
func TestIDTokenKeysRotate(t *testing.T) {
	p := oidcrptest.New(t, testClientID, testClientSecret)
	c, now, rules := verifier(t, p, "nonce-1")
	jwks := p.JWKSURL()
	claims := func() jwt.MapClaims { return p.Claims("nonce-1", "user-1", "asha@example.test") }
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, claims(), nil, ""), jwks, rules); err != nil {
		t.Fatal(err)
	}
	p.Rotate(t, "key-2")
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, claims(), nil, ""), jwks, rules); err == nil || p.Fetches() != 1 {
		t.Errorf("a new key straight after a fetch: %v after %d fetches; want refused without fetching again", err, p.Fetches())
	}
	*now = now.Add(keysMinRefresh + time.Second)
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, claims(), nil, ""), jwks, rules); err != nil || p.Fetches() != 2 {
		t.Errorf("a rotated key: %v after %d fetches; want accepted after one more", err, p.Fetches())
	}
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, claims(), nil, ""), jwks, rules); err != nil || p.Fetches() != 2 {
		t.Errorf("the rotated key again: %v after %d fetches; want it cached", err, p.Fetches())
	}

	ec := newECKey(t)
	p.Publish(oidcrptest.ECJWK("ec-1", &ec.PublicKey))
	*now = now.Add(keysMinRefresh + time.Second)
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, claims(), ec, "ec-1"), jwks, rules); err != nil {
		t.Errorf("a token signed with a published EC key: %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), p.Sign(t, claims(), newECKey(t), "ec-1"), jwks, rules); err == nil {
		t.Error("a token signed by another EC key under the published kid was accepted")
	}
}

// TestIDTokenTenants checks that a provider serving many tenants signs in only
// the tenants the rules list, or any when they list none, each under its own
// issuer.
func TestIDTokenTenants(t *testing.T) {
	p := oidcrptest.New(t, testClientID, testClientSecret)
	c, _, rules := verifier(t, p, "nonce-1")
	jwks := p.JWKSURL()
	const mine, theirs = "6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11", "0e3b5f11-1111-4c2a-8f2e-7a1d3c9b2e22"
	rules = RulesFor(Discovery{Issuer: "https://login.example.test/{tenantid}/v2.0"}, testClientID, rules.NonceHash)
	token := func(iss, tid string) string {
		claims := p.Claims("nonce-1", "user-1", "asha@example.test")
		claims["iss"] = iss
		if tid != "" {
			claims["tid"] = tid
		}
		return p.Sign(t, claims, nil, "")
	}
	if _, err := c.VerifyIDToken(context.Background(), token("https://login.example.test/"+theirs+"/v2.0", theirs), jwks, rules); err != nil {
		t.Errorf("any tenant's token, with none listed: %v", err)
	}
	rules.TenantIDs = []string{mine}
	if _, err := c.VerifyIDToken(context.Background(), token("https://login.example.test/"+mine+"/v2.0", mine), jwks, rules); err != nil {
		t.Errorf("a token from a listed tenant: %v", err)
	}
	for name, raw := range map[string]string{
		"from a tenant not listed":                    token("https://login.example.test/"+theirs+"/v2.0", theirs),
		"naming a listed tenant under another issuer": token("https://login.example.test/"+theirs+"/v2.0", mine),
		"naming no tenant":                            token("https://login.example.test/"+mine+"/v2.0", ""),
		"from the template itself":                    token(rules.IssuerTemplate, mine),
	} {
		if _, err := c.VerifyIDToken(context.Background(), raw, jwks, rules); err == nil {
			t.Errorf("a token %s was accepted", name)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

// TestDiscoveryChecksTheDocument checks that a discovery document is used only
// with an issuer, token endpoint and keys, and an authorization endpoint the
// browser can safely be sent to, and that a refused one isn't cached.
func TestDiscoveryChecksTheDocument(t *testing.T) {
	complete := Discovery{Issuer: "https://idp.example.com", AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint: "https://idp.example.com/token", JWKSURI: "https://idp.example.com/jwks"}
	cases := map[string]func(*Discovery){
		"no issuer":         func(d *Discovery) { d.Issuer = "" },
		"no token endpoint": func(d *Discovery) { d.TokenEndpoint = "" },
		"no keys":           func(d *Discovery) { d.JWKSURI = "" },
	}
	for _, endpoint := range []string{
		"http://idp.example.com/authorize", "javascript:alert(1)", "data:text/html,hi", "//idp.example.com/authorize",
		"/authorize", "https:///authorize", "https:idp.example.com/authorize", "https://user:pass@idp.example.com/authorize",
		"https://idp.example.com/authorize#frag", "https://idp.example.com/authorize#", "https://idp.example.com/\tauthorize",
	} {
		cases["authorization endpoint "+endpoint] = func(d *Discovery) { d.AuthorizationEndpoint = endpoint }
	}
	const discoveryURL = "https://idp.example.com/.well-known/openid-configuration"
	serve := func(doc Discovery) *Client {
		raw, _ := json.Marshal(doc)
		c := New(egress.PublicPolicy())
		c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
		})}
		return c
	}
	if got, err := serve(complete).Discover(context.Background(), discoveryURL); err != nil || got.Issuer != complete.Issuer {
		t.Fatalf("a complete document: %+v, %v", got, err)
	}
	for _, endpoint := range []string{"https://idp.example.com:8443/oauth2/v1/authorize?tenant=a"} {
		doc := complete
		doc.AuthorizationEndpoint = endpoint
		if _, err := serve(doc).Discover(context.Background(), discoveryURL); err != nil {
			t.Errorf("authorization endpoint %s: %v", endpoint, err)
		}
	}
	for name, change := range cases {
		doc := complete
		change(&doc)
		c := serve(doc)
		if _, err := c.Discover(context.Background(), discoveryURL); err == nil {
			t.Errorf("a document with %s was used", name)
		}
		if _, cached := c.docs[discoveryURL]; cached {
			t.Errorf("a document with %s was cached", name)
		}
	}
}

// TestRequestsFollowTheOutboundPolicy checks that every request to a
// provider, its discovery document, keys, token and userinfo endpoints, goes
// only where the outbound policy allows: a secret is never sent over plain
// http or to a local address.
func TestRequestsFollowTheOutboundPolicy(t *testing.T) {
	sent := 0
	c := New(egress.PublicPolicy())
	c.http = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	})}
	ctx := context.Background()
	insecure := Discovery{Issuer: "https://idp.example.com", TokenEndpoint: "http://idp.example.com/token",
		UserinfoEndpoint: "http://idp.example.com/userinfo", JWKSURI: "http://idp.example.com/jwks"}
	if _, err := c.Discover(ctx, "http://idp.example.com/.well-known/openid-configuration"); err == nil {
		t.Error("a discovery document over http was read")
	}
	if _, err := c.Exchange(ctx, insecure, Credentials{ClientID: "id", ClientSecret: "secret"}, "code", "https://id.example.test/cb", ""); err == nil {
		t.Error("a code was traded over http")
	}
	if err := c.Userinfo(ctx, insecure, "token", &struct{}{}); err == nil {
		t.Error("userinfo was read over http")
	}
	if _, err := c.VerifyIDToken(ctx, "a.b.c", insecure.JWKSURI, Rules{Issuer: insecure.Issuer, ClientID: "id", NonceHash: "n"}); err == nil {
		t.Error("keys were read over http")
	}
	local := Discovery{TokenEndpoint: "https://127.0.0.1/token"}
	if _, err := c.Exchange(ctx, local, Credentials{ClientID: "id", ClientSecret: "secret"}, "code", "https://id.example.test/cb", ""); err == nil {
		t.Error("a code was traded with a local address")
	}
	if sent != 0 {
		t.Errorf("%d requests sent past the policy", sent)
	}
}

// TestExchangeAuthenticatesAsTheProviderAllows checks that the client sends
// its secret by HTTP Basic unless the provider supports only the form.
func TestExchangeAuthenticatesAsTheProviderAllows(t *testing.T) {
	p := oidcrptest.New(t, testClientID, testClientSecret)
	c := New(egress.DevelopmentPolicy())
	cred := Credentials{ClientID: testClientID, ClientSecret: testClientSecret}
	for _, methods := range [][]string{nil, {"client_secret_basic"}, {"client_secret_post"}, {"client_secret_post", "client_secret_basic"}} {
		p.SetAuthMethods(methods)
		doc := Discovery{TokenEndpoint: p.URL + "/token", TokenAuthMethods: methods}
		p.Expect("code-1", oidcrptest.Grant{Challenge: codes.Hash("verifier"), IDToken: "id-token"})
		if got, err := c.Exchange(context.Background(), doc, cred, "code-1", "https://id.example.test/cb", "verifier"); err != nil || got.IDToken != "id-token" || got.AccessToken == "" {
			t.Errorf("methods %v: %+v, %v", methods, got, err)
		}
	}
	p.Expect("code-2", oidcrptest.Grant{})
	if _, err := c.Exchange(context.Background(), Discovery{TokenEndpoint: p.URL + "/token"}, Credentials{ClientID: testClientID, ClientSecret: "wrong"}, "code-2", "https://id.example.test/cb", ""); err == nil {
		t.Error("a code was traded with the wrong secret")
	}
}
