//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// carriesToken reports whether a response hands a token to whoever reads it:
// in its body, or in the address it sends the browser to.
func carriesToken(rr *httptest.ResponseRecorder) bool {
	seen := rr.Body.String() + " " + rr.Header().Get("Location")
	for _, name := range []string{"access_token", "refresh_token", "id_token"} {
		if strings.Contains(seen, name) {
			return true
		}
	}
	return false
}

// TestHostedSignInAnswersCarryNoTokens: backend token pairs never reach browser
// script, yet passkey sign-in finish answered the hosted sign-in page with a
// full access and refresh token pair as well as the cookie, so a script on that
// page read a thirty-day renewal credential at every passkey sign-in. Passkey
// sign-in now has a hosted form that sets only the cookie and a token form that
// sets none. Every hosted sign-in answer — password, second factor,
// registration, magic link, passkey, passkey registration and social — sets
// the cookie and carries no token.
func TestHostedSignInAnswersCarryNoTokens(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	setSelfRegistration(t, ctx, f.tenantID, true)
	hosted := func(t *testing.T, flow string, rr *httptest.ResponseRecorder, wantStatus int) {
		t.Helper()
		if rr.Code != wantStatus || !setsCookie(rr, auth.LoginSessionCookie) || carriesToken(rr) {
			t.Fatalf("%s = %d (cookie %v) %s %s; want %d, the hosted-login cookie and no token",
				flow, rr.Code, setsCookie(rr, auth.LoginSessionCookie), rr.Header().Get("Location"), rr.Body.String(), wantStatus)
		}
	}

	t.Run("password", func(t *testing.T) {
		_, email := f.member(t, ctx)
		hosted(t, "password sign-in", f.post("/v1/auth/session", map[string]string{"email": email, "password": factorPassword}), http.StatusOK)
	})

	t.Run("password and a second factor", func(t *testing.T) {
		id, email := f.member(t, ctx)
		secret := f.holdTOTP(t, ctx, id)
		rr := f.post("/v1/auth/session", map[string]string{"email": email, "password": factorPassword})
		var c challenge
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &c) != nil || c.MFAToken == "" || carriesToken(rr) {
			t.Fatalf("password step = %d %s; want a challenge and no token", rr.Code, rr.Body.String())
		}
		hosted(t, "second factor", f.post("/v1/auth/session/mfa", map[string]any{"mfa_token": c.MFAToken, "code": totpCodeAtStep(t, secret, 0)}), http.StatusOK)
	})

	t.Run("registration", func(t *testing.T) {
		hosted(t, "registration", f.post("/v1/auth/register", map[string]string{
			"tenant_id": f.tenantID.String(), "email": uniqueSlug("joiner") + "@example.com", "password": factorPassword,
		}), http.StatusCreated)
	})

	t.Run("magic link", func(t *testing.T) {
		_, email := f.member(t, ctx)
		hosted(t, "magic link", f.post("/v1/auth/magic-link/session", map[string]string{"token": f.hostedLink(t, email)}), http.StatusOK)
	})

	passkeys := chi.NewRouter()
	passkeys.Route("/v1", (&passkey.Handler{Service: f.passkeys}).MountPublic)

	t.Run("passkey", func(t *testing.T) {
		pk := newPasskeyAccount(t, ctx, f.passkeys)
		b := newBrowser()
		hosted(t, "passkey sign-in", pk.post(passkeys, b, "/v1/passkeys/login/session", "application/json", pk.begin(t, passkeys, b)), http.StatusOK)

		// The token form answers the console's server with a pair, and no
		// cookie — even in a browser that began the ceremony.
		rr := pk.post(passkeys, b, "/v1/passkeys/login/finish", "application/json", pk.begin(t, passkeys, b))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "refresh_token") || setsCookie(rr, auth.LoginSessionCookie) {
			t.Fatalf("token form = %d (cookie %v); want a token pair and no cookie", rr.Code, setsCookie(rr, auth.LoginSessionCookie))
		}
	})

	t.Run("passkey registration", func(t *testing.T) {
		post := func(path string, body any) *httptest.ResponseRecorder {
			raw, _ := json.Marshal(body)
			return (&passkeyAccount{}).post(passkeys, newBrowser(), path, "application/json", raw)
		}
		rr := post("/v1/register/passkey/begin", map[string]string{"tenant_id": f.tenantID.String(), "email": uniqueSlug("pk-joiner") + "@example.com"})
		var begun struct {
			SessionID uuid.UUID       `json:"session_id"`
			PublicKey json.RawMessage `json:"publicKey"`
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &begun) != nil {
			t.Fatalf("registration begin = %d %s", rr.Code, rr.Body.String())
		}
		creation, _ := json.Marshal(map[string]json.RawMessage{"publicKey": begun.PublicKey})
		opts, err := virtualwebauthn.ParseAttestationOptions(string(creation))
		if err != nil {
			t.Fatal(err)
		}
		a := virtualwebauthn.NewAuthenticator()
		a.Options.UserHandle = []byte(opts.UserID)
		attestation := virtualwebauthn.CreateAttestationResponse(virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin},
			a, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *opts)
		hosted(t, "passkey registration", post("/v1/register/passkey/finish", map[string]any{
			"session_id": begun.SessionID, "credential": json.RawMessage(attestation), "name": "Laptop",
		}), http.StatusCreated)
	})

	t.Run("social", func(t *testing.T) {
		sub := uniqueSlug("social")
		idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true}`, sub, sub+"@example.com"))
		t.Cleanup(idp.Close)
		provider := uniqueSlug("idp")
		if _, err := testPool.Exec(ctx, `
			INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
			VALUES ($1, $2, 'cid', 'csecret', $3)`, f.tenantID, provider, idp.URL+"/.well-known/openid-configuration"); err != nil {
			t.Fatal(err)
		}
		svc := social.NewService(testPool, f.auth, "http://app.local", egress.DevelopmentPolicy())
		svc.SetCipher(testEnvelope(t))
		svc.SetAllowedReturnOrigins("https://app.example")
		router := chi.NewRouter()
		router.Route("/v1", (&social.Handler{Service: svc, LoginBaseURL: "http://login.test"}).MountPublic)
		b := newBrowser()
		rr := b.do(router, httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/start?"+url.Values{
			"tenant_id": {f.tenantID.String()}, "return_to": {"https://app.example/oauth/authorize?client_id=rp"}}.Encode(), nil))
		loc, _ := url.Parse(rr.Header().Get("Location"))
		hosted(t, "social sign-in", b.do(router, httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/callback?"+
			url.Values{"state": {loc.Query().Get("state")}, "code": {"upstream-code"}}.Encode(), nil)), http.StatusFound)
	})
}
