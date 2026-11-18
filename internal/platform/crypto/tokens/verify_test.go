package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestVerifyAccess_RoundTrip(t *testing.T) {
	i, _ := testIssuer(t)
	uid, tid, sid := uuid.New(), uuid.New(), uuid.New()
	tok, _, err := i.IssueAccess(uid, tid, sid, "scope.a scope.b")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.UserID != uid || c.OrganizationID != tid || c.SessionID != sid {
		t.Errorf("claims round-trip mismatch: %+v", c)
	}
	if c.Scope != "scope.a scope.b" {
		t.Errorf("scope mismatch: %q", c.Scope)
	}
}

func TestVerifyAccess_SurfacesActorClaims(t *testing.T) {
	// Agent/service tokens carry actor_type/agent_id (custom claims); verify they
	// round-trip into Claims so introspection can surface them.
	i, _ := testIssuer(t)
	now := time.Now().UTC()
	tok, err := i.Sign(Claims{
		OrganizationID: uuid.New(),
		Scope:          "vault:read",
		ActorType:      "agent",
		AgentID:        "agent-xyz",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "qeet-test",
			Audience:  jwt.ClaimStrings{"qeet-test"},
			Subject:   uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	c, err := i.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if c.ActorType != "agent" || c.AgentID != "agent-xyz" {
		t.Errorf("actor claims not surfaced: actor_type=%q agent_id=%q", c.ActorType, c.AgentID)
	}
}

func TestVerifyVC_RoundTripAndRejection(t *testing.T) {
	i, _ := testIssuer(t)
	now := time.Now().UTC()
	type vcClaims struct {
		VC map[string]any `json:"vc"`
		jwt.RegisteredClaims
	}
	make := func(iss string) string {
		s, err := i.Sign(vcClaims{
			VC: map[string]any{"type": []string{"VerifiableCredential", "TestCred"}},
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    iss,
				Subject:   "did:example:123",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	// Our credential verifies and the vc claim is accessible.
	claims, err := i.VerifyVC(make("qeet-test"))
	if err != nil {
		t.Fatalf("VerifyVC: %v", err)
	}
	if _, ok := claims["vc"].(map[string]any); !ok {
		t.Error("vc claim missing from verified credential")
	}
	// A credential claiming a different issuer must be rejected.
	if _, err := i.VerifyVC(make("evil-issuer")); err == nil {
		t.Error("VerifyVC must reject a foreign issuer")
	}
}

// TestVerifyVC_AcceptsOnlyCredentials checks that the issuer's other tokens,
// which verify as signed, are not taken for verifiable credentials.
func TestVerifyVC_AcceptsOnlyCredentials(t *testing.T) {
	i, _ := testIssuer(t)
	user, organization, session := uuid.New(), uuid.New(), uuid.New()
	exp := time.Now().Add(time.Hour).Unix()
	sign := func(claims jwt.MapClaims) string {
		s, err := i.Sign(claims)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}
	access, _, err := i.IssueAccess(user, organization, session, "openid")
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	clientAccess, _, err := i.IssueClientAccess(ClientAccess{UserID: user, OrganizationID: organization, SessionID: session, ClientID: "qci_app"})
	if err != nil {
		t.Fatalf("client access: %v", err)
	}
	others := map[string]string{
		"access token":            access,
		"client access token":     clientAccess,
		"ID token":                sign(jwt.MapClaims{"iss": "qeet-test", "sub": user.String(), "aud": "qci_app", "exp": exp}),
		"sign-out ticket":         sign(jwt.MapClaims{"iss": "qeet-test", "typ": "logout_confirmation", "sid": session.String(), "exp": exp}),
		"vc without its type":     sign(jwt.MapClaims{"iss": "qeet-test", "vc": map[string]any{"type": []string{"Other"}}, "exp": exp}),
		"vc that isn't an object": sign(jwt.MapClaims{"iss": "qeet-test", "vc": "VerifiableCredential", "exp": exp}),
	}
	for name, raw := range others {
		if _, err := i.VerifySigned(raw); err != nil {
			t.Errorf("%s: VerifySigned: %v", name, err)
		}
		if _, err := i.VerifyVC(raw); !errors.Is(err, ErrNotCredential) {
			t.Errorf("%s: VerifyVC = %v, want %v", name, err, ErrNotCredential)
		}
	}
	single := sign(jwt.MapClaims{"iss": "qeet-test", "vc": map[string]any{"type": "VerifiableCredential"}, "exp": exp})
	if _, err := i.VerifyVC(single); err != nil {
		t.Errorf("a credential with a single type: %v", err)
	}
}

func TestVerifyAccess_RejectsTokenWithoutKID(t *testing.T) {
	i, priv := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": i.JWTIssuer(), "aud": i.JWTAudience(), "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	delete(tok.Header, "kid")
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("must reject token with no kid header")
	} else if !strings.Contains(err.Error(), "kid") {
		t.Errorf("error should mention kid: %v", err)
	}
}

func TestVerifyAccess_RejectsUnknownKID(t *testing.T) {
	i, priv := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": i.JWTIssuer(), "aud": i.JWTAudience(), "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "definitely-not-a-real-kid"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("must reject token with unknown kid")
	}
}

// TestVerifyAccess_RejectsHS256Token guards against the classic "alg confusion"
// attack: a token forged with HS256 (treating the public key as an HMAC secret)
// must be rejected because the parser only accepts ES256.
func TestVerifyAccess_RejectsHS256Token(t *testing.T) {
	i, _ := testIssuer(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": i.JWTIssuer(), "aud": i.JWTAudience(), "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = i.KID()
	signed, err := tok.SignedString([]byte("attacker-chosen-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.VerifyAccess(signed); err == nil {
		t.Error("must reject an HS256-signed token (alg confusion)")
	}
}

func TestVerifyAccess_AcceptsRetiredKeyDuringGraceWindow(t *testing.T) {
	oldIssuer, oldPriv := testIssuer(t)
	oldToken, _, err := oldIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	// Post-rotation issuer with a new active key; register the old PUBLIC key.
	newIssuer, _ := testIssuer(t)
	if n := newIssuer.AddRetiredKeysPEM(publicPEM(t, oldPriv)); n != 1 {
		t.Fatalf("AddRetiredKeysPEM registered %d keys, want 1", n)
	}
	if _, err := newIssuer.VerifyAccess(oldToken); err != nil {
		t.Errorf("retired key should still verify old tokens: %v", err)
	}
	// And the new primary still verifies its own tokens.
	newToken, _, _ := newIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	if _, err := newIssuer.VerifyAccess(newToken); err != nil {
		t.Errorf("new primary should verify its own tokens: %v", err)
	}
}

func TestVerifyAccess_RejectsTokenAfterRetiredKeyDropped(t *testing.T) {
	oldIssuer, _ := testIssuer(t)
	oldToken, _, _ := oldIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	newIssuer, _ := testIssuer(t) // no retired key registered
	if _, err := newIssuer.VerifyAccess(oldToken); err == nil {
		t.Error("old token must not verify once the retired key is dropped")
	}
}

func TestVerifyAccess_RejectsTamperedKIDHeader(t *testing.T) {
	i, _ := testIssuer(t)
	tok, _, _ := i.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "")
	parts := strings.Split(tok, ".")
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": "tampered"})
	parts[0] = base64.RawURLEncoding.EncodeToString(hdr)
	if _, err := i.VerifyAccess(strings.Join(parts, ".")); err == nil {
		t.Error("tampered kid header must be rejected")
	}
}

// TestAKeyVerifiesOnlyItsOwnAlgorithm checks that a token naming a key under
// the other accepted algorithm is refused before its signature is looked at.
func TestAKeyVerifiesOnlyItsOwnAlgorithm(t *testing.T) {
	i, _ := testIssuer(t)
	if n := i.AddRetiredKeysPEM(publicPEM(t, rsaKey())); n != 1 {
		t.Fatalf("%d retired keys added, want the RSA key", n)
	}
	kids := map[string]string{}
	for _, k := range i.JWKS() {
		kids[k.Alg] = k.Kid
	}
	for _, c := range []struct {
		method jwt.SigningMethod
		kid    string
		ok     bool
	}{
		{jwt.SigningMethodES256, kids["ES256"], true},
		{jwt.SigningMethodRS256, kids["RS256"], true},
		{jwt.SigningMethodES256, kids["RS256"], false},
		{jwt.SigningMethodRS256, kids["ES256"], false},
	} {
		_, err := i.keyFunc(&jwt.Token{Method: c.method, Header: map[string]any{"kid": c.kid}})
		if (err == nil) != c.ok {
			t.Errorf("a %s token naming the %s key: %v, want accepted=%t", c.method.Alg(), c.kid, err, c.ok)
		}
	}
}

// fuzzSigningInput returns the "header.payload" part of a compact JWT.
func fuzzSigningInput(raw string) string {
	if i := strings.LastIndex(raw, "."); i >= 0 {
		return raw[:i]
	}
	return raw
}

func fuzzSegment(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// FuzzVerifyAccess checks that the token verifiers never panic on an arbitrary
// string, return exactly one of claims or an error, and accept only tokens
// whose signed header and payload this test's key produced.
func FuzzVerifyAccess(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("genkey: %v", err)
	}
	issuer, err := newIssuerFromKey(priv, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		f.Fatalf("issuer: %v", err)
	}

	signed := map[string]bool{}
	sign := func(header map[string]any, claims jwt.Claims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		for k, v := range header {
			if v == nil {
				delete(tok.Header, k)
				continue
			}
			tok.Header[k] = v
		}
		raw, err := tok.SignedString(priv)
		if err != nil {
			f.Fatalf("sign: %v", err)
		}
		signed[fuzzSigningInput(raw)] = true
		return raw
	}
	registered := func(iss string, exp time.Time) jwt.RegisteredClaims {
		return jwt.RegisteredClaims{
			Issuer:    iss,
			Audience:  jwt.ClaimStrings{"qeet-test"},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}
	}

	valid, _, err := issuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
	if err != nil {
		f.Fatalf("issue: %v", err)
	}
	signed[fuzzSigningInput(valid)] = true
	kid := map[string]any{"kid": issuer.KID()}
	seeds := []string{
		valid,
		sign(kid, &Claims{UserID: uuid.New(), RegisteredClaims: registered("qeet-test", time.Now().Add(-time.Hour))}),
		sign(kid, &Claims{RegisteredClaims: registered("someone-else", time.Now().Add(time.Hour))}),
		sign(map[string]any{"kid": nil}, &Claims{RegisteredClaims: registered("qeet-test", time.Now().Add(time.Hour))}),
		sign(map[string]any{"kid": "unknown"}, &Claims{RegisteredClaims: registered("qeet-test", time.Now().Add(time.Hour))}),
		sign(map[string]any{"kid": 7}, &Claims{RegisteredClaims: registered("qeet-test", time.Now().Add(time.Hour))}),
		sign(kid, jwt.MapClaims{"iss": "qeet-test", "aud": "qeet-test", "exp": "soon", "user_id": "not-a-uuid"}),
		sign(kid, jwt.MapClaims{"iss": []string{"qeet-test"}, "claims": map[string]any{"a": 1}, "act": "x"}),
	}
	header := fuzzSegment(`{"alg":"ES256","typ":"JWT","kid":"` + issuer.KID() + `"}`)
	payload := fuzzSegment(`{"iss":"qeet-test","aud":"qeet-test","exp":4102444800,"user_id":"` + uuid.NewString() + `"}`)
	seeds = append(seeds,
		fuzzSegment(`{"alg":"none","typ":"JWT"}`)+"."+payload+".",
		fuzzSegment(`{"alg":"HS256","kid":"`+issuer.KID()+`"}`)+"."+payload+".c2lnbmF0dXJl",
		fuzzSegment(`{"alg":"ES384","kid":"`+issuer.KID()+`"}`)+"."+payload+"."+strings.Repeat("A", 128),
		header+"."+payload+"."+strings.Repeat("A", 86),
		header+"."+payload,
		header+"."+payload+"."+fuzzSegment("short"),
		header+".."+strings.Repeat("A", 86),
		fuzzSegment(`{"alg":"ES256","kid":{"nested":[1,2,3]}}`)+"."+payload+".AAAA",
		fuzzSegment(`[]`)+"."+fuzzSegment(`null`)+".AAAA",
		valid[:len(valid)-1],
		valid+".extra",
		strings.Replace(valid, ".", "..", 1),
		"Bearer "+valid,
		"eyJ.eyJ.eyJ",
		"a.b.c",
		"...",
		".",
		"",
	)
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		checkAccess := func(name string, claims *Claims, err error) {
			if (claims == nil) == (err == nil) {
				t.Fatalf("%s(%q) = (%v, %v), want exactly one of claims or error", name, raw, claims, err)
			}
			if err == nil && (!signed[fuzzSigningInput(raw)] || claims.Issuer != "qeet-test") {
				t.Fatalf("%s accepted a token this key did not sign: %q", name, raw)
			}
		}
		claims, err := issuer.VerifyAccess(raw)
		checkAccess("VerifyAccess", claims, err)
		claims, err = issuer.VerifyAccessFor(raw, "resource.example")
		checkAccess("VerifyAccessFor", claims, err)
		claims, err = issuer.VerifyAccessAnyAudience(raw)
		checkAccess("VerifyAccessAnyAudience", claims, err)

		checkMap := func(name string, claims jwt.MapClaims, err error) {
			if (claims == nil) == (err == nil) {
				t.Fatalf("%s(%q) = (%v, %v), want exactly one of claims or error", name, raw, claims, err)
			}
			if err == nil && !signed[fuzzSigningInput(raw)] {
				t.Fatalf("%s accepted a token this key did not sign: %q", name, raw)
			}
		}
		mapClaims, err := issuer.VerifyVC(raw)
		checkMap("VerifyVC", mapClaims, err)
		mapClaims, err = issuer.VerifySigned(raw)
		checkMap("VerifySigned", mapClaims, err)
		mapClaims, err = issuer.VerifySignedAnyTime(raw)
		checkMap("VerifySignedAnyTime", mapClaims, err)
	})
}
