package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp/oidcrptest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const testAppleClientID = "com.qeet.test"

// appleSide returns a service whose Apple endpoints are p's, and p, which
// issues tokens as Apple does.
func appleSide(t *testing.T) (*Service, *oidcrptest.Provider) {
	t.Helper()
	p := oidcrptest.New(t, testAppleClientID, "apple-client-secret")
	p.SetIssuer(appleIssuer)
	s := NewService(nil, nil, "https://console.example.test", egress.DevelopmentPolicy())
	s.apple.TokenEndpoint, s.apple.JWKSURI = p.URL+"/token", p.JWKSURL()
	return s, p
}

func validAppleClaims(nonce string) jwt.MapClaims {
	now := time.Now().UTC()
	return jwt.MapClaims{
		"iss":            appleIssuer,
		"aud":            testAppleClientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"sub":            "apple-user-123",
		"email":          "verified@example.com",
		"email_verified": true,
		"nonce":          nonce,
	}
}

// TestAppleIDTokenValidation checks that Sign in with Apple signs someone in
// only on an ID token Apple's published key signed with RS256, from Apple,
// for this Services ID, current, carrying the sign-in's nonce and a verified
// address.
func TestAppleIDTokenValidation(t *testing.T) {
	s, p := appleSide(t)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.Publish(oidcrptest.ECJWK("ec-1", &ec.PublicKey))
	const nonce = "one-time-nonce"
	with := func(change func(jwt.MapClaims)) jwt.MapClaims {
		c := validAppleClaims(nonce)
		change(c)
		return c
	}
	hmac := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, validAppleClaims(nonce))
		token.Header["kid"] = "key-1"
		raw, err := token.SignedString([]byte("not-an-apple-rsa-key"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	noKid := func() string {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, validAppleClaims(nonce)).SignedString(stranger)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	signIn := func(token string) (userInfo, error) {
		p.Expect("code", oidcrptest.Grant{IDToken: token})
		return s.appleSignIn(context.Background(), testAppleClientID, "apple-client-secret", "code", "https://id.example.test/cb", codes.Hash(nonce))
	}

	info, err := signIn(p.Sign(t, validAppleClaims(nonce), nil, ""))
	if err != nil || info.Subject != "apple-user-123" || info.Email != "verified@example.com" || !info.EmailVerified {
		t.Fatalf("a valid token: %+v, %v", info, err)
	}
	for name, token := range map[string]string{
		"with an invalid signature": p.Sign(t, validAppleClaims(nonce), stranger, "key-1"),
		"under an unknown kid":      p.Sign(t, validAppleClaims(nonce), stranger, "unknown"),
		"naming no key":             noKid(),
		"signed with HS256":         hmac(),
		"signed with ES256":         p.Sign(t, validAppleClaims(nonce), ec, "ec-1"),
		"from another issuer":       p.Sign(t, with(func(c jwt.MapClaims) { c["iss"] = "https://attacker.example" }), nil, ""),
		"for another client":        p.Sign(t, with(func(c jwt.MapClaims) { c["aud"] = "other-client" }), nil, ""),
		"expired":                   p.Sign(t, with(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }), nil, ""),
		"without an issue time":     p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "iat") }), nil, ""),
		"without a nonce":           p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "nonce") }), nil, ""),
		"with another nonce":        p.Sign(t, validAppleClaims("different-nonce"), nil, ""),
		"with an unverified email":  p.Sign(t, with(func(c jwt.MapClaims) { c["email_verified"] = false }), nil, ""),
		"without an email":          p.Sign(t, with(func(c jwt.MapClaims) { delete(c, "email") }), nil, ""),
		"none at all":               "",
	} {
		if info, err := signIn(token); err == nil {
			t.Errorf("a token %s was accepted: %+v", name, info)
		}
	}
	p.Expect("code", oidcrptest.Grant{IDToken: p.Sign(t, validAppleClaims(nonce), nil, "")})
	if _, err := s.appleSignIn(context.Background(), testAppleClientID, "wrong-secret", "code", "https://id.example.test/cb", codes.Hash(nonce)); err == nil {
		t.Error("a code was traded with the wrong client secret")
	}
}
