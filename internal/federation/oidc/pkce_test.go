package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// TestPKCE_S256ChallengeDerivation checks that the stored code_challenge is
// BASE64URL(SHA256(verifier)) without padding, which ExchangeCode relies on.
func TestPKCE_S256ChallengeDerivation(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 §A.1 verifier
	challenge := codes.Hash(verifier)

	// Independently compute the canonical S256 challenge and compare.
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("codes.Hash(verifier) = %q, want canonical S256 %q", challenge, want)
	}
	// No base64 padding (PKCE challenges are unpadded base64url).
	if strings.Contains(challenge, "=") {
		t.Errorf("S256 challenge must be unpadded base64url, got %q", challenge)
	}

	// The verification predicate ExchangeCode uses: a matching verifier passes,
	// a tampered one fails.
	if codes.Hash(verifier) != challenge {
		t.Error("the correct verifier must reproduce the challenge")
	}
	if codes.Hash(verifier+"x") == challenge {
		t.Error("a tampered verifier must not reproduce the challenge")
	}
}

// TestValidateSignInRequest checks that an authorization request needs an S256
// challenge unless a confidential application is exempt, and that a nonce is
// optional either way but bounded when sent.
func TestValidateSignInRequest(t *testing.T) {
	challenge := strings.Repeat("c", 43)
	for _, tc := range []struct {
		name                     string
		clientType               string
		exempt                   bool
		nonce, challenge, method string
		want                     error
	}{
		{"a public application with PKCE and a nonce", "public", false, "n-1", challenge, "S256", nil},
		{"a public application with PKCE and no nonce", "public", false, "", challenge, "S256", nil},
		{"a confidential application with PKCE and no nonce", "confidential", false, "", challenge, "S256", nil},
		{"an exempt confidential application with neither", "confidential", true, "", "", "", nil},
		{"no challenge", "confidential", false, "n-1", "", "", ErrCodeChallengeRequired},
		{"no challenge from an exempt public application", "public", true, "n-1", "", "", ErrCodeChallengeRequired},
		{"a plain challenge", "public", false, "", challenge, "plain", ErrCodeChallengeMethodUnsupported},
		{"a method without a challenge", "confidential", true, "", "", "S256", ErrCodeChallengeInvalid},
		{"a nonce too long", "public", false, strings.Repeat("n", maxNonceLength+1), challenge, "S256", ErrNonceInvalid},
	} {
		if err := validateSignInRequest(tc.clientType, tc.exempt, tc.nonce, tc.challenge, tc.method); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}
