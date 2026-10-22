package social

// Sign in with Apple needs its own flow: the client secret is a short-lived
// ES256 JWT signed with a .p8 key, the callback arrives as a form_post, and the
// identity comes from the verified id_token since there is no userinfo endpoint.
// The name Apple sends only on first sign-in is not used.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

const (
	appleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL     = "https://appleid.apple.com/auth/token"
	appleJWKSURL      = "https://appleid.apple.com/auth/keys"
	appleAudience     = "https://appleid.apple.com"
	appleScopes       = "name email"
	appleJWKSTTL      = time.Hour
)

type cachedAppleKeys struct {
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
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
		"aud": appleAudience,
		"sub": servicesID,
	})
	tok.Header["kid"] = keyID
	return tok.SignedString(key)
}

// appleExchange trades the code for tokens and cryptographically validates the
// returned ID token against Apple's rotating JWKS before using identity claims.
func (c *oauthClient) appleExchange(ctx context.Context, clientSecret, servicesID, code, redirectURI, nonceHash string) (userInfo, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {servicesID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.appleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return userInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return userInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return userInfo{}, fmt.Errorf("apple token endpoint: status %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return userInfo{}, err
	}
	if tok.IDToken == "" {
		return userInfo{}, errors.New("apple: no id_token")
	}
	return c.verifyAppleIDToken(ctx, tok.IDToken, servicesID, nonceHash)
}

func (c *oauthClient) verifyAppleIDToken(ctx context.Context, raw, servicesID, nonceHash string) (userInfo, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(appleAudience),
		jwt.WithAudience(servicesID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Minute),
	)
	token, err := parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("apple: id_token must use RS256")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("apple: id_token missing kid")
		}
		return c.appleVerificationKey(ctx, kid)
	})
	if err != nil || !token.Valid {
		return userInfo{}, fmt.Errorf("apple: verify id_token: %w", err)
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil || issuedAt == nil {
		return userInfo{}, errors.New("apple: id_token missing or invalid iat")
	}
	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return userInfo{}, errors.New("apple: id_token missing sub")
	}
	nonce, _ := claims["nonce"].(string)
	if nonceHash == "" || nonce == "" || subtle.ConstantTimeCompare([]byte(codes.Hash(nonce)), []byte(nonceHash)) != 1 {
		return userInfo{}, errors.New("apple: id_token nonce mismatch")
	}
	email, _ := claims["email"].(string)
	if email == "" || !appleEmailVerified(claims["email_verified"]) {
		return userInfo{}, errors.New("apple: id_token email is not verified")
	}
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

func (c *oauthClient) appleVerificationKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, cacheHit, err := c.loadAppleKeys(ctx, false)
	if err != nil {
		return nil, err
	}
	if key := keys[kid]; key != nil {
		return key, nil
	}
	if cacheHit {
		keys, _, err = c.loadAppleKeys(ctx, true)
		if err != nil {
			return nil, err
		}
		if key := keys[kid]; key != nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("apple: unknown id_token kid %q", kid)
}

func (c *oauthClient) loadAppleKeys(ctx context.Context, force bool) (map[string]*rsa.PublicKey, bool, error) {
	c.appleMu.Lock()
	if !force && len(c.appleKeys.keys) > 0 && time.Now().Before(c.appleKeys.expiresAt) {
		keys := c.appleKeys.keys
		c.appleMu.Unlock()
		return keys, true, nil
	}
	c.appleMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.appleJWKSURL, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("apple JWKS: status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, false, fmt.Errorf("apple JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.KID == "" || jwk.KTY != "RSA" || jwk.Alg != "RS256" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			continue
		}
		exponent := 0
		for _, b := range exponentBytes {
			exponent = exponent<<8 | int(b)
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
		if key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
			continue
		}
		keys[jwk.KID] = key
	}
	if len(keys) == 0 {
		return nil, false, errors.New("apple JWKS: no usable RS256 signing keys")
	}
	c.appleMu.Lock()
	c.appleKeys = cachedAppleKeys{keys: keys, expiresAt: time.Now().Add(appleJWKSTTL)}
	c.appleMu.Unlock()
	return keys, false, nil
}
