package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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
