package social

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

const testAppleClientID = "com.qeet.test"

func appleSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func appleJWK(kid string, key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kid": kid,
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signedAppleToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign Apple token: %v", err)
	}
	return raw
}

func signedAppleHMACToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "key-1"
	raw, err := token.SignedString([]byte("not-an-apple-rsa-key"))
	if err != nil {
		t.Fatalf("sign HMAC Apple token: %v", err)
	}
	return raw
}

func validAppleClaims(nonce string) jwt.MapClaims {
	now := time.Now().UTC()
	return jwt.MapClaims{
		"iss":            appleAudience,
		"aud":            testAppleClientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"sub":            "apple-user-123",
		"email":          "verified@example.com",
		"email_verified": true,
		"nonce":          nonce,
	}
}

func appleVerifier(t *testing.T, keys func() []map[string]string) (*oauthClient, *int) {
	t.Helper()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys()})
	}))
	t.Cleanup(server.Close)
	return &oauthClient{http: server.Client(), appleJWKSURL: server.URL}, &requests
}

func TestAppleIDTokenValidation(t *testing.T) {
	key := appleSigningKey(t)
	otherKey := appleSigningKey(t)
	client, _ := appleVerifier(t, func() []map[string]string { return []map[string]string{appleJWK("key-1", &key.PublicKey)} })
	const nonce = "one-time-nonce"
	nonceHash := codes.Hash(nonce)

	tests := []struct {
		name   string
		key    *rsa.PrivateKey
		kid    string
		claims jwt.MapClaims
		valid  bool
	}{
		{name: "valid", key: key, kid: "key-1", claims: validAppleClaims(nonce), valid: true},
		{name: "invalid signature", key: otherKey, kid: "key-1", claims: validAppleClaims(nonce)},
		{name: "unknown kid", key: key, kid: "unknown", claims: validAppleClaims(nonce)},
		{name: "wrong issuer", key: key, kid: "key-1", claims: func() jwt.MapClaims { c := validAppleClaims(nonce); c["iss"] = "https://attacker.example"; return c }()},
		{name: "wrong audience", key: key, kid: "key-1", claims: func() jwt.MapClaims { c := validAppleClaims(nonce); c["aud"] = "other-client"; return c }()},
		{name: "expired", key: key, kid: "key-1", claims: func() jwt.MapClaims {
			c := validAppleClaims(nonce)
			c["exp"] = time.Now().Add(-2 * time.Minute).Unix()
			return c
		}()},
		{name: "missing issued at", key: key, kid: "key-1", claims: func() jwt.MapClaims { c := validAppleClaims(nonce); delete(c, "iat"); return c }()},
		{name: "missing nonce", key: key, kid: "key-1", claims: func() jwt.MapClaims { c := validAppleClaims(nonce); delete(c, "nonce"); return c }()},
		{name: "wrong nonce", key: key, kid: "key-1", claims: validAppleClaims("different-nonce")},
		{name: "unverified email", key: key, kid: "key-1", claims: func() jwt.MapClaims { c := validAppleClaims(nonce); c["email_verified"] = false; return c }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := signedAppleToken(t, test.key, test.kid, test.claims)
			info, err := client.verifyAppleIDToken(context.Background(), raw, testAppleClientID, nonceHash)
			if test.valid {
				if err != nil {
					t.Fatalf("valid token rejected: %v", err)
				}
				if info.Subject != "apple-user-123" || info.Email != "verified@example.com" || !info.EmailVerified {
					t.Fatalf("unexpected verified identity: %+v", info)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid Apple token was accepted")
			}
		})
	}
	missingKID := jwt.NewWithClaims(jwt.SigningMethodRS256, validAppleClaims(nonce))
	rawMissingKID, err := missingKID.SignedString(key)
	if err != nil {
		t.Fatalf("sign token without kid: %v", err)
	}
	if _, err := client.verifyAppleIDToken(context.Background(), rawMissingKID, testAppleClientID, nonceHash); err == nil {
		t.Fatal("Apple token without kid was accepted")
	}
	if _, err := client.verifyAppleIDToken(context.Background(), signedAppleHMACToken(t, validAppleClaims(nonce)), testAppleClientID, nonceHash); err == nil {
		t.Fatal("Apple token with substituted algorithm was accepted")
	}
}

func TestAppleJWKSRefreshesOnUnknownKID(t *testing.T) {
	firstKey := appleSigningKey(t)
	secondKey := appleSigningKey(t)
	var mu sync.Mutex
	activeKid := "first"
	activeKey := &firstKey.PublicKey
	client, requests := appleVerifier(t, func() []map[string]string {
		mu.Lock()
		defer mu.Unlock()
		return []map[string]string{appleJWK(activeKid, activeKey)}
	})
	const nonce = "rotation-nonce"
	if _, err := client.verifyAppleIDToken(context.Background(), signedAppleToken(t, firstKey, "first", validAppleClaims(nonce)), testAppleClientID, codes.Hash(nonce)); err != nil {
		t.Fatalf("verify first key: %v", err)
	}
	mu.Lock()
	activeKid = "second"
	activeKey = &secondKey.PublicKey
	mu.Unlock()
	if _, err := client.verifyAppleIDToken(context.Background(), signedAppleToken(t, secondKey, "second", validAppleClaims(nonce)), testAppleClientID, codes.Hash(nonce)); err != nil {
		t.Fatalf("verify rotated key: %v", err)
	}
	if *requests != 2 {
		t.Fatalf("JWKS requests = %d, want initial fetch plus one refresh", *requests)
	}
}
