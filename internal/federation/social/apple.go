package social

// Sign in with Apple needs its own flow: the client secret is a short-lived
// ES256 JWT signed with a .p8 key, the callback arrives as a form_post, and the
// identity comes from the verified ID token since there is no userinfo endpoint.
// The name Apple sends only on first sign-in is not used.

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
)

const (
	appleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL     = "https://appleid.apple.com/auth/token" // #nosec G101 -- public endpoint URL
	appleJWKSURL      = "https://appleid.apple.com/auth/keys"
	appleIssuer       = "https://appleid.apple.com" // the ID tokens' issuer, and the client secrets' audience
	appleScopes       = "name email"
)

// appleProvider is Apple's provider as a discovery document would describe
// it. Apple takes the client secret only in the form.
var appleProvider = oidcrp.Discovery{
	Issuer: appleIssuer, TokenEndpoint: appleTokenURL, JWKSURI: appleJWKSURL,
	TokenAuthMethods: []string{"client_secret_post"},
}

// appleClientSecret builds Apple's client secret — a short-lived ES256 JWT
// signed with the .p8 private key, per Apple's "Creating a client secret" spec.
func appleClientSecret(servicesID, teamID, keyID, privateKeyPEM string) (string, error) {
	// Allow the .p8 to be provided on a single env line with escaped newlines.
	pemStr := strings.ReplaceAll(privateKeyPEM, `\n`, "\n")
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", errors.New("apple: private key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("apple: parse private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("apple: private key is not ECDSA")
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(30 * time.Minute).Unix(),
		"aud": appleIssuer,
		"sub": servicesID,
	})
	tok.Header["kid"] = keyID
	return tok.SignedString(key)
}

// appleSignIn trades the code for Apple's ID token and returns whom it signs
// in, once the token is verified against Apple's keys (RS256 only) for
// servicesID and the sign-in's nonce, with a verified address.
func (s *Service) appleSignIn(ctx context.Context, servicesID, clientSecret, code, redirectURI, nonceHash string) (userInfo, error) {
	tokens, err := s.oidc.Exchange(ctx, s.apple, oidcrp.Credentials{ClientID: servicesID, ClientSecret: clientSecret}, code, redirectURI, "")
	if err != nil {
		return userInfo{}, err
	}
	if tokens.IDToken == "" {
		return userInfo{}, errors.New("apple: no id_token")
	}
	claims, err := s.oidc.VerifyIDToken(ctx, tokens.IDToken, s.apple.JWKSURI, oidcrp.Rules{
		Issuer: s.apple.Issuer, ClientID: servicesID, NonceHash: nonceHash, Algorithms: []string{"RS256"},
	})
	if err != nil {
		return userInfo{}, fmt.Errorf("apple: verify id_token: %w", err)
	}
	email, _ := claims["email"].(string)
	if email == "" || !appleEmailVerified(claims["email_verified"]) {
		return userInfo{}, errors.New("apple: id_token email is not verified")
	}
	sub, _ := claims["sub"].(string)
	return userInfo{Subject: sub, Email: email, EmailVerified: true}, nil
}

func appleEmailVerified(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}
