//go:build integration

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 authenticator codes are HMAC-SHA1
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/tests/apitest"
)

const appRedirect = "https://app.example.test/callback"

// discovery is the provider metadata the journey uses.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// TestApplicationSignsAPersonIn runs the authorization code flow with PKCE as an application and a
// browser run it: the owner registers the application; the person signs in on the hosted login and
// approves it; the application redeems the code for an ID token signed with a key the provider
// publishes, naming the person, the application and the nonce; and userinfo names the person.
func TestApplicationSignsAPersonIn(t *testing.T) {
	s := apitest.Start(t)
	owner := s.NewOwner()
	recovery := stepUp(t, s, owner)
	clientID, secret := registerApplication(t, s, owner)

	var meta discovery
	s.Do(http.MethodGet, "/.well-known/openid-configuration", "", nil).Want(t, http.StatusOK).JSON(t, &meta)

	// The hosted login: the password, then the second factor the owner now holds.
	browser := s.Browser()
	var challenge struct {
		MFAToken string `json:"mfa_token"`
	}
	browser.Do(http.MethodPost, "/v1/auth/session", map[string]string{"email": owner.Email, "password": owner.Password, "client_id": clientID}).
		Want(t, http.StatusOK).JSON(t, &challenge)
	if challenge.MFAToken == "" || browser.Has("qe_ls") {
		t.Fatal("the hosted login opened a session without the second factor")
	}
	browser.Do(http.MethodPost, "/v1/auth/session/mfa", map[string]string{"mfa_token": challenge.MFAToken, "code": recovery[1]}).Want(t, http.StatusOK)
	if !browser.Has("qe_ls") {
		t.Fatal("meeting the second factor on the hosted login set no session cookie")
	}

	verifier := base64.RawURLEncoding.EncodeToString(randomBytes(t))
	pkce := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {appRedirect}, "scope": {"openid email"},
		"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(pkce[:])}, "code_challenge_method": {"S256"},
	}
	callback := approve(t, browser, path(meta.AuthorizationEndpoint)+"?"+query.Encode())
	if callback.Query().Get("state") != "st-1" || callback.Query().Get("code") == "" {
		t.Fatalf("the application got %s, want its redirect with a code and its state", callback)
	}

	tokens := redeem(t, s, path(meta.TokenEndpoint), clientID, secret, url.Values{
		"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {appRedirect}, "code_verifier": {verifier},
	})
	claims := verifyIDToken(t, s, path(meta.JWKSURI), tokens.IDToken)
	if claims["iss"] != meta.Issuer || claims["sub"] != owner.UserID.String() || claims["nonce"] != "n-1" || !audience(claims, clientID) {
		t.Errorf("ID token claims %v, want iss %s, sub %s, aud %s and nonce n-1", claims, meta.Issuer, owner.UserID, clientID)
	}

	var info struct {
		Sub string `json:"sub"`
	}
	s.Do(http.MethodGet, path(meta.UserinfoEndpoint), tokens.AccessToken, nil).Want(t, http.StatusOK).JSON(t, &info)
	if info.Sub != owner.UserID.String() {
		t.Errorf("userinfo names %s, want %s", info.Sub, owner.UserID)
	}
}

// stepUp sets up an authenticator app for the owner, as registering an application needs a recent
// second factor, and steps their session up with a recovery code. It returns the recovery codes.
func stepUp(t *testing.T, s *apitest.Server, owner apitest.Owner) []string {
	t.Helper()
	var enrolment struct {
		Secret string `json:"secret"`
	}
	s.Do(http.MethodPost, "/v1/mfa/totp/enroll/start", owner.Token, map[string]string{}).Want(t, http.StatusOK).JSON(t, &enrolment)
	var confirmed struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	s.Do(http.MethodPost, "/v1/mfa/totp/enroll/confirm", owner.Token, map[string]string{"code": totp(t, enrolment.Secret, time.Now())}).
		Want(t, http.StatusOK).JSON(t, &confirmed)
	if len(confirmed.RecoveryCodes) < 2 {
		t.Fatalf("enrolment returned %d recovery codes, want several", len(confirmed.RecoveryCodes))
	}
	s.Do(http.MethodPost, "/v1/mfa/totp/verify", owner.Token, map[string]string{"code": confirmed.RecoveryCodes[0]}).Want(t, http.StatusOK)
	return confirmed.RecoveryCodes
}

// totp is the RFC 6238 code an authenticator app shows for secret at now: HMAC-SHA1, 30s, 6 digits.
func totp(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("authenticator secret %q: %v", secret, err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30)) // #nosec G115 -- a positive Unix time
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// registerApplication registers a confidential web application in the owner's organization.
func registerApplication(t *testing.T, s *apitest.Server, owner apitest.Owner) (string, string) {
	t.Helper()
	var app struct {
		Client struct {
			ClientID string `json:"client_id"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	s.Do(http.MethodPost, "/v1/organizations/"+owner.OrganizationID.String()+"/oidc/clients", owner.Token, map[string]any{
		"organization_id": owner.OrganizationID, "name": "Journey App", "type": "confidential",
		"redirect_uris": []string{appRedirect}, "grant_types": []string{"authorization_code", "refresh_token"},
	}).Want(t, http.StatusCreated).JSON(t, &app)
	return app.Client.ClientID, app.ClientSecret
}

// approve sends the browser to the authorization request and approves the consent screen if it is
// shown, returning where the application is sent back to.
func approve(t *testing.T, browser *apitest.Browser, target string) *url.URL {
	t.Helper()
	res := browser.Do(http.MethodGet, target, nil).Want(t, http.StatusFound)
	to := res.Location()
	if !strings.HasSuffix(to.Path, "/consent") {
		return to
	}
	var decided struct {
		Redirect string `json:"redirect"`
	}
	browser.Do(http.MethodPost, "/v1/oauth/authorize/decision", map[string]any{"request_id": to.Query().Get("request_id"), "approve": true}).
		Want(t, http.StatusOK).JSON(t, &decided)
	back, err := url.Parse(decided.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	return back
}

// tokenResponse is the token endpoint's answer.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// redeem posts form to the token endpoint with the client's credentials.
func redeem(t *testing.T, s *apitest.Server, endpoint, clientID, secret string, form url.Values) tokenResponse {
	t.Helper()
	var out tokenResponse
	s.Send(func() *http.Request {
		req := s.Form(http.MethodPost, endpoint, form)
		req.SetBasicAuth(clientID, secret)
		return req
	}).Want(t, http.StatusOK).JSON(t, &out)
	return out
}

// verifyIDToken checks the ID token's signature with the provider's published keys and returns its claims.
func verifyIDToken(t *testing.T, s *apitest.Server, jwksPath, raw string) jwt.MapClaims {
	t.Helper()
	var set struct {
		Keys []struct {
			Kid, Kty, Crv, X, Y string
		} `json:"keys"`
	}
	s.Do(http.MethodGet, jwksPath, "", nil).Want(t, http.StatusOK).JSON(t, &set)
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		for _, k := range set.Keys {
			if k.Kid == token.Header["kid"] && k.Kty == "EC" && k.Crv == "P-256" {
				point := append(append([]byte{4}, coordinate(t, k.X)...), coordinate(t, k.Y)...)
				return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("ID token doesn't verify with the published keys: %v", err)
	}
	return claims
}

func audience(claims jwt.MapClaims, clientID string) bool {
	aud, _ := claims.GetAudience()
	for _, a := range aud {
		if a == clientID {
			return true
		}
	}
	return false
}

// coordinate decodes a JWK's base64url P-256 coordinate into its 32 bytes, left-padded.
func coordinate(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) > 32 {
		t.Fatalf("JWK coordinate %q: %v", s, err)
	}
	return append(make([]byte, 32-len(b)), b...)
}

func randomBytes(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// path is the path of an endpoint the discovery document names, served by the test server.
func path(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	return u.Path
}
