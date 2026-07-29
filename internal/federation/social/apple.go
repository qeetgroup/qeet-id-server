package social

// Sign in with Apple adapter. Apple publishes an OIDC discovery doc but differs
// enough to need its own path: the client secret is a short-lived ES256 JWT
// signed with a .p8 key (not a static string), the authorize flow uses
// response_mode=form_post (so the callback is a POST), and there is no userinfo
// endpoint — the subject and email come from the id_token returned by the token
// exchange. Apple only sends the user's name on the very first authorization
// (in the form_post "user" field), so we don't rely on it here.

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	appleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL     = "https://appleid.apple.com/auth/token"
	appleAudience     = "https://appleid.apple.com"
	appleScopes       = "name email"
)

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

// appleExchange trades the code for tokens and returns the identity read from
// the id_token (Apple has no userinfo endpoint). The id_token comes straight
// from Apple's TLS token endpoint, so its claims are read without re-verifying
// against Apple's JWKS.
func (c *oauthClient) appleExchange(ctx context.Context, clientSecret, servicesID, code, redirectURI string) (userInfo, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {servicesID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL, strings.NewReader(form.Encode()))
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
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok.IDToken, claims); err != nil {
		return userInfo{}, fmt.Errorf("apple: parse id_token: %w", err)
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if sub == "" {
		return userInfo{}, errors.New("apple: id_token missing sub")
	}
	return userInfo{Subject: sub, Email: email}, nil
}
