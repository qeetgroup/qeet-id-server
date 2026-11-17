//go:build integration

package social

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
)

// oauth2Provider is a fake OAuth 2.0 provider for the adapters: it accepts a
// code it was told about, checking the client's authentication and, for X,
// the PKCE verifier, and answers its user endpoint as the adapter expects.
type oauth2Provider struct {
	*httptest.Server
	mu    sync.Mutex
	users map[string]string // access token → user JSON
	auth  map[string]string // code → how the client authenticated
}

func newOAuth2Provider(t *testing.T) *oauth2Provider {
	p := &oauth2Provider{users: map[string]string{}, auth: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.PostForm.Get("code")
		how := "form"
		if id, secret, ok := r.BasicAuth(); ok && id == "client" && secret == "secret" {
			how = "basic:" + r.PostForm.Get("code_verifier")
		} else if r.PostForm.Get("client_secret") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p.mu.Lock()
		p.auth[code] = how
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at-" + code})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		body, ok := p.users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		p.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// appleKeyPEM is a fresh .p8-style PKCS#8 ECDSA P-256 key.
func appleKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestOrganisationAdaptersSignIn checks that an organisation adds GitHub,
// Facebook, X, Discord and Apple without a discovery URL, Apple only with a
// key that signs; that each starts at its own authorize endpoint, X with PKCE
// and Apple by form_post with a nonce; and that Discord and X sign-ins adopt
// a member's account through the adapter, while Facebook's unverified address
// never adopts one.
func TestOrganisationAdaptersSignIn(t *testing.T) {
	f := newSocialFixture(t)
	idp := newOAuth2Provider(t)
	f.svc.oauth.endpoints = map[string]oauth2Endpoints{}
	for kind, ep := range defaultEndpoints {
		ep.authorizeURL, ep.tokenURL, ep.userURL = "https://"+kind+".example.test/authorize", idp.URL+"/token", idp.URL+"/user"
		f.svc.oauth.endpoints[kind] = ep
	}
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), f.mount)
	add := func(body map[string]string) *httptest.ResponseRecorder {
		return dbtest.Do(t, asAdmin, http.MethodPost, "/social/providers", body)
	}
	for _, name := range []string{"github", "facebook", "x", "discord"} {
		if rec := add(map[string]string{"provider": name, "client_id": "client", "client_secret": "secret"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kind":"`+name+`"`) {
			t.Fatalf("add %s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := add(map[string]string{"provider": "apple", "client_id": "in.qeet.signin", "client_secret": appleKeyPEM(t)}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("Apple without its team and key ids: %d, want 422", rec.Code)
	}
	if rec := add(map[string]string{"provider": "apple", "client_id": "in.qeet.signin", "client_secret": "not a key", "apple_team_id": "TEAM123456", "apple_key_id": "KEY1234567"}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("Apple with a key that can't sign: %d, want 422", rec.Code)
	}
	if rec := add(map[string]string{"provider": "apple", "client_id": "in.qeet.signin", "client_secret": appleKeyPEM(t), "apple_team_id": "TEAM123456", "apple_key_id": "KEY1234567"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"apple_team_id":"TEAM123456"`) || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Errorf("Apple with its key: %d %s", rec.Code, rec.Body.String())
	}

	start := func(provider string) (*httptest.ResponseRecorder, *url.URL) {
		t.Helper()
		rec := browse(t, f.public, http.MethodGet, "/social/"+provider+"/start?tenant_id="+tenant.String(), nil, nil)
		u, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || err != nil {
			t.Fatalf("start %s: %d %s", provider, rec.Code, rec.Body.String())
		}
		return rec, u
	}
	if _, u := start("github"); u.Host != "github.com" || u.Query().Get("state") == "" || u.Query().Get("code_challenge") != "" {
		t.Errorf("GitHub starts at %s; want GitHub's authorize, with state and no PKCE", u)
	}
	if _, u := start("apple"); u.Host != "appleid.apple.com" || u.Query().Get("response_mode") != "form_post" || u.Query().Get("nonce") == "" {
		t.Errorf("Apple starts at %s; want form_post with a nonce", u)
	}

	signIn := func(provider, userJSON string) (*httptest.ResponseRecorder, string) {
		t.Helper()
		begun, u := start(provider)
		code := uuid.NewString()
		idp.mu.Lock()
		idp.users["at-"+code] = userJSON
		idp.mu.Unlock()
		rec := browse(t, f.public, http.MethodGet, "/social/"+provider+"/callback?state="+url.QueryEscape(u.Query().Get("state"))+"&code="+code, begun.Result().Cookies(), nil)
		idp.mu.Lock()
		defer idp.mu.Unlock()
		return rec, idp.auth[code] + "|" + u.Query().Get("code_challenge")
	}
	gamer := dbtest.User(t, tenant, tenant)
	verified(t, gamer)
	email := gamer.Email
	rec, _ := signIn("discord", `{"id":"d-1","username":"gamer","global_name":"Gamer","email":"`+email+`","verified":true}`)
	if target, q := redirectQuery(t, rec); target != "https://console.example.test/auth/social/callback" || q.Get("code") == "" {
		t.Fatalf("Discord sign-in went to %s %v", target, q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users u JOIN account.external_identities e ON e.user_id = u.id
		WHERE u.email = $1 AND u.email_verified_at IS NOT NULL AND e.provider = 'discord' AND e.subject = 'd-1' AND e.tenant_id = $2`, email, tenant); n != 1 {
		t.Errorf("Discord sign-in made %d verified, linked accounts; want 1", n)
	}

	ex := dbtest.User(t, tenant, tenant)
	verified(t, ex)
	rec, how := signIn("x", `{"data":{"id":"x-1","name":"Ex","username":"ex","confirmed_email":"`+ex.Email+`"}}`)
	if _, q := redirectQuery(t, rec); q.Get("code") == "" {
		t.Errorf("X sign-in: %v", q)
	}
	parts := strings.SplitN(how, "|", 2)
	if verifier, ok := strings.CutPrefix(parts[0], "basic:"); !ok || codes.Hash(verifier) != parts[1] {
		t.Errorf("X's token request authenticated as %q; want HTTP Basic with the PKCE verifier", how)
	}

	member := dbtest.User(t, tenant, tenant)
	verified(t, member)
	rec, _ = signIn("facebook", `{"id":"fb-1","name":"Asha","email":"`+member.Email+`"}`)
	if _, q := redirectQuery(t, rec); q.Get("code") != "" {
		t.Errorf("Facebook's unverified address adopted an existing account: %v", q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, member.ID); n != 0 {
		t.Errorf("%d identities linked to the existing account, want none", n)
	}
}
