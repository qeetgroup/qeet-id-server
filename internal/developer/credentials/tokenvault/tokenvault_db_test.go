//go:build integration

package tokenvault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// oauthProvider is a fake third-party authorization server. Its code exchange
// issues an access token that is already due for refresh, so the next read
// refreshes it.
type oauthProvider struct {
	*httptest.Server
	mu    sync.Mutex
	forms []url.Values
}

// newOAuthProvider starts the provider until t ends.
func newOAuthProvider(t *testing.T) *oauthProvider {
	p := &oauthProvider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.forms = append(p.forms, r.PostForm)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.PostForm.Get("client_secret") != "provider-client-secret":
			w.WriteHeader(http.StatusUnauthorized)
		case r.PostForm.Get("grant_type") == "authorization_code" && r.PostForm.Get("code") == "good-code":
			_, _ = w.Write([]byte(`{"access_token":"access-1","refresh_token":"refresh-1","expires_in":"30","scope":"read"}`))
		case r.PostForm.Get("grant_type") == "refresh_token" && r.PostForm.Get("refresh_token") == "refresh-1":
			_, _ = w.Write([]byte(`{"access_token":"access-2","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

// lastForm is the latest token request the provider received.
func (p *oauthProvider) lastForm() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.forms) == 0 {
		return nil
	}
	return p.forms[len(p.forms)-1]
}

// s256 is a PKCE verifier's S256 challenge.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// exchanges counts the token requests the provider received.
func (p *oauthProvider) exchanges() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.forms)
}

// vaultService returns the vault, allowed to call loopback providers.
func vaultService(t *testing.T) *Service {
	t.Helper()
	return NewService(dbtest.Pool(t), testCipher(t), egress.DevelopmentPolicy())
}

// testCipher returns a cipher over a fixed data key.
func testCipher(t *testing.T) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// signedIn is p as a person's own session holding scopes.
func signedIn(p *httpx.Principal, scopes ...string) *httpx.Principal {
	sid := uuid.New()
	p.SessionID, p.Scopes = &sid, scopes
	return p
}

// TestConnectedAccountLifecycle checks that an organisation registers a
// provider without its secret ever being returned, a person connects an
// account once per ceremony, only in the browser that began it and with its
// PKCE verifier, its token is refreshed when due and given only to that person
// signed in with the scope, and it can be disconnected.
func TestConnectedAccountLifecycle(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := vaultService(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	provider := newOAuthProvider(t)
	vault := &Handler{Service: svc, PublicBaseURL: "https://id.example.test"}
	asPerson := dbtest.Serve(signedIn(dbtest.Principal(person.ID, tenant), "vault:acme"), vault.Mount)
	public := chi.NewRouter()
	vault.MountPublic(public)
	providers := "/tenants/" + tenant.String() + "/vault/tokens/providers"

	rec := dbtest.Do(t, asPerson, http.MethodPost, providers, map[string]string{
		"provider": "acme", "client_id": "qeet-client", "client_secret": "provider-client-secret",
		"authorize_url": provider.URL + "/authorize?prompt=consent", "token_url": provider.URL + "/token", "scopes": "read",
	})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "provider-client-secret") {
		t.Fatalf("register provider: %d %s; want 201 without the secret", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asPerson, http.MethodGet, providers, nil); !strings.Contains(rec.Body.String(), `"acme"`) || strings.Contains(rec.Body.String(), "provider-client-secret") {
		t.Errorf("providers: %s; want acme without its secret", rec.Body.String())
	}

	var browser []*http.Cookie // the person's browser: the cookies it holds now
	keep := func(rec *httptest.ResponseRecorder) {
		for _, set := range rec.Result().Cookies() {
			kept := browser[:0]
			for _, c := range browser {
				if c.Name != set.Name {
					kept = append(kept, c)
				}
			}
			browser = kept
			if set.MaxAge >= 0 {
				browser = append(browser, set)
			}
		}
	}
	send := func(h http.Handler, target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	challenges := map[string]string{}
	connect := func() string {
		t.Helper()
		rec := send(asPerson, "/vault/tokens/acme/connect", browser)
		keep(rec)
		var out struct {
			AuthorizeURL string `json:"authorize_url"`
		}
		dbtest.Decode(t, rec, &out)
		u, err := url.Parse(out.AuthorizeURL)
		if err != nil || !strings.HasPrefix(out.AuthorizeURL, provider.URL+"/authorize?") {
			t.Fatalf("connect: %d %s", rec.Code, rec.Body.String())
		}
		q := u.Query()
		if q.Get("client_id") != "qeet-client" || q.Get("redirect_uri") != "https://id.example.test/v1/vault/tokens/callback" || q.Get("scope") != "read" || q.Get("prompt") != "consent" {
			t.Errorf("authorize URL %s; want the client, the fixed callback, the scopes and the provider's own parameters", out.AuthorizeURL)
		}
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			t.Errorf("authorize URL %s; want a PKCE challenge", out.AuthorizeURL)
		}
		challenges[q.Get("state")] = q.Get("code_challenge")
		return q.Get("state")
	}
	callback := func(query string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		rec := send(public, "/vault/tokens/callback?"+query, cookies)
		if cookies != nil {
			keep(rec)
		}
		return rec
	}
	stolen := connect()
	if rec := callback("state="+stolen+"&code=good-code", nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "another browser") || provider.exchanges() != 0 {
		t.Errorf("a ceremony finished in another browser: %d %s; want refused before any exchange", rec.Code, rec.Body.String())
	}
	state := connect()
	if rec := callback("state="+state+"&code=good-code", browser); rec.Code != http.StatusOK {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body.String())
	}
	if form := provider.lastForm(); form.Get("code_verifier") == "" || s256(form.Get("code_verifier")) != challenges[state] {
		t.Errorf("code exchange %v; want the verifier of the ceremony's challenge", form)
	}
	if rec := callback("state="+state+"&code=good-code", browser); rec.Code != http.StatusBadRequest {
		t.Errorf("the same callback twice: %d, want refused", rec.Code)
	}
	for name, query := range map[string]string{
		"refused at the provider": "error=access_denied",
		"without a code":          "state=" + connect(),
		"with an unknown state":   "state=forged&code=good-code",
		"with a bad code":         "state=" + connect() + "&code=bad-code",
	} {
		if rec := callback(query, browser); rec.Code != http.StatusBadRequest {
			t.Errorf("a callback %s: %d, want refused", name, rec.Code)
		}
	}
	expired := connect()
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.token_vault_connect_states SET expires_at = now() - interval '1 minute' WHERE state = $1`, expired); err != nil {
		t.Fatal(err)
	}
	if rec := callback("state="+expired+"&code=good-code", browser); !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("an expired ceremony: %d %s", rec.Code, rec.Body.String())
	}

	if rec := dbtest.Do(t, asPerson, http.MethodGet, "/vault/tokens", nil); !strings.Contains(rec.Body.String(), `"provider":"acme"`) || strings.Contains(rec.Body.String(), "access-1") {
		t.Errorf("connected accounts: %s; want acme without its tokens", rec.Body.String())
	}
	accessToken := func(h http.Handler) (int, string) {
		rec := dbtest.Do(t, h, http.MethodGet, "/vault/tokens/acme/access-token", nil)
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if rec.Code == http.StatusOK {
			dbtest.Decode(t, rec, &out)
		}
		return rec.Code, out.AccessToken + rec.Body.String()
	}
	before := provider.exchanges()
	if code, token := accessToken(asPerson); code != http.StatusOK || !strings.HasPrefix(token, "access-2") {
		t.Errorf("a token due for refresh: %d %s; want the refreshed one", code, token)
	}
	if code, token := accessToken(asPerson); code != http.StatusOK || !strings.HasPrefix(token, "access-2") || provider.exchanges() != before+1 {
		t.Errorf("a live token: %d %s after %d exchanges; want it without another", code, token, provider.exchanges()-before)
	}
	if got := provider.forms[len(provider.forms)-1]; got.Get("refresh_token") != "refresh-1" || got.Get("client_id") != "qeet-client" {
		t.Errorf("refresh sent %v; want the stored refresh token and the client", got)
	}

	for name, p := range map[string]*httpx.Principal{
		"an API key":           {UserID: &person.ID, TenantID: &tenant, ActorType: "api_key", Subject: "key-1", Scopes: []string{"vault:read"}},
		"an application":       {UserID: &person.ID, TenantID: &tenant, ActorType: "user", ClientID: "app", SessionID: &person.ID, Scopes: []string{"vault:read"}},
		"without a session":    {UserID: &person.ID, TenantID: &tenant, ActorType: "user", Scopes: []string{"vault:read"}},
		"without the scope":    signedIn(dbtest.Principal(person.ID, tenant), "vault:other"),
		"another person":       signedIn(dbtest.Principal(dbtest.User(t, tenant, tenant).ID, tenant), "vault:read"),
		"another organisation": signedIn(dbtest.Principal(person.ID, other), "vault:read"),
	} {
		if code, body := accessToken(dbtest.Serve(p, vault.Mount)); code == http.StatusOK || strings.Contains(body, "access-2") {
			t.Errorf("%s read the token: %d %s", name, code, body)
		}
	}
	var refused int
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'vault.tokens.access_refused'`, tenant).Scan(&refused); err != nil || refused != 3 {
		t.Errorf("%d refused reads recorded (%v), want the three credentials that aren't a signed-in person", refused, err)
	}

	if rec := dbtest.Do(t, asPerson, http.MethodDelete, "/vault/tokens/acme", nil); rec.Code != http.StatusNoContent {
		t.Errorf("disconnect: %d", rec.Code)
	}
	if code, body := accessToken(asPerson); !strings.Contains(body, errs.CodeTokenVaultGrantNotFound) {
		t.Errorf("after disconnecting: %d %s", code, body)
	}
	if rec := dbtest.Do(t, asPerson, http.MethodDelete, providers+"/acme", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete provider: %d", rec.Code)
	}
	if rec := dbtest.Do(t, asPerson, http.MethodGet, "/vault/tokens/acme/connect", nil); !strings.Contains(rec.Body.String(), errs.CodeTokenVaultProviderNotFound) {
		t.Errorf("connect to a deleted provider: %d %s", rec.Code, rec.Body.String())
	}
}

// TestProviderSecretIsEncryptedOnUse checks that a provider stored with a
// plaintext client secret works and has it encrypted the first time it's used,
// and that a provider at a private address is refused.
func TestProviderSecretIsEncryptedOnUse(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := vaultService(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant.token_vault_providers (tenant_id, provider, client_id, client_secret, authorize_url, token_url)
		VALUES ($1, 'legacy', 'qeet-client', 'older-plain-secret', 'https://auth.example.test/authorize', 'https://auth.example.test/token')
	`, tenant); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := svc.BeginConnect(ctx, tenant, person.ID, "legacy", "https://id.example.test"); err != nil {
			t.Fatal(err)
		}
	}
	var plain string
	var version int
	if err := pool.QueryRow(ctx, `SELECT client_secret, encryption_version FROM tenant.token_vault_providers WHERE tenant_id = $1`, tenant).Scan(&plain, &version); err != nil {
		t.Fatal(err)
	}
	if plain != "" || version != 1 {
		t.Errorf("after use the client secret is %q at version %d; want it encrypted", plain, version)
	}
	if _, _, _, _, _, err := svc.providerConfig(ctx, tenant, "legacy"); err != nil {
		t.Errorf("read the encrypted secret: %v", err)
	}

	strict := NewService(pool, testCipher(t))
	if _, err := strict.RegisterProvider(ctx, tenant, RegisterProviderInput{
		Provider: "internal", ClientID: "c", ClientSecret: "s", AuthorizeURL: "http://127.0.0.1:9/authorize", TokenURL: "http://127.0.0.1:9/token",
	}); err == nil {
		t.Error("a provider at a private address was registered")
	}
}

// connected stores a grant of person's for provider, as a finished connect
// ceremony would.
func connected(t *testing.T, tenant, person uuid.UUID, provider string) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO tenant.token_vault_grants (tenant_id, user_id, provider, access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce)
		VALUES ($1, $2, $3, 'ct', 'nonce', 'ct', 'nonce')`, tenant, person, provider); err != nil {
		t.Fatal(err)
	}
}

// TestTokenVaultEndpointsCannotChangeUnderLiveGrants checks that while anyone
// is connected through a provider its token URL, authorize URL and client
// can't change, nor can deleting and adding it again hand its grants to new
// endpoints, so a refresh token goes only to the endpoint it came from; the
// secret and scopes still change, and an unused provider changes freely.
func TestTokenVaultEndpointsCannotChangeUnderLiveGrants(t *testing.T) {
	svc := vaultService(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	admin := dbtest.Serve(dbtest.Principal(dbtest.User(t, tenant, tenant).ID, tenant), (&Handler{Service: svc}).Mount)
	providers := "/tenants/" + tenant.String() + "/vault/tokens/providers"
	settings := map[string]string{
		"provider": "acme", "client_id": "qeet-client", "client_secret": "secret-1",
		"authorize_url": "https://auth.acme.example/authorize", "token_url": "https://auth.acme.example/token", "scopes": "read",
	}
	with := func(key, value string) map[string]string {
		out := map[string]string{}
		for k, v := range settings {
			out[k] = v
		}
		out[key] = value
		return out
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, settings); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	connected(t, tenant, person.ID, "acme")
	for key, value := range map[string]string{
		"token_url":     "https://collector.example/token",
		"authorize_url": "https://collector.example/authorize",
		"client_id":     "other-client",
	} {
		if rec := dbtest.Do(t, admin, http.MethodPost, providers, with(key, value)); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeTokenVaultProviderInUse) {
			t.Errorf("change %s under a live grant: %d %s, want 409 %s", key, rec.Code, rec.Body.String(), errs.CodeTokenVaultProviderInUse)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.token_vault_providers WHERE tenant_id = $1 AND token_url = 'https://auth.acme.example/token' AND client_id = 'qeet-client'`, tenant); n != 1 {
		t.Error("a refused change was stored")
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, with("client_secret", "secret-2")); rec.Code != http.StatusCreated {
		t.Errorf("rotate the client secret under a live grant: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, with("scopes", "read write")); rec.Code != http.StatusCreated {
		t.Errorf("change the scopes under a live grant: %d %s, want 201", rec.Code, rec.Body.String())
	}

	if rec := dbtest.Do(t, admin, http.MethodDelete, providers+"/acme", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.token_vault_grants WHERE tenant_id = $1 AND provider = 'acme'`, tenant); n != 0 {
		t.Errorf("%d grants kept by a deleted provider, want none", n)
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, with("token_url", "https://collector.example/token")); rec.Code != http.StatusCreated {
		t.Errorf("register again, with nobody connected, at another token URL: %d %s, want 201", rec.Code, rec.Body.String())
	}
	connected(t, tenant, person.ID, "orphaned")
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, with("provider", "orphaned")); rec.Code != http.StatusConflict {
		t.Errorf("register a provider whose name still has grants: %d %s, want 409", rec.Code, rec.Body.String())
	}
}

// TestAGrantIsKeptOnlyUnderTheEndpointItCameFrom checks that tokens a
// provider's token URL issued are not stored once the provider has been
// pointed elsewhere while they were being fetched, so its refresh token can't
// later go to the new endpoint.
func TestAGrantIsKeptOnlyUnderTheEndpointItCameFrom(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := vaultService(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	issuing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The provider is repointed while its token request is in flight.
		if _, err := dbtest.Pool(t).Exec(context.Background(), `UPDATE tenant.token_vault_providers SET token_url = 'https://collector.example/token' WHERE tenant_id = $1`, tenant); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`))
	}))
	t.Cleanup(issuing.Close)
	if _, err := svc.RegisterProvider(ctx, tenant, RegisterProviderInput{Provider: "acme", ClientID: "qeet-client", ClientSecret: "secret",
		AuthorizeURL: issuing.URL + "/authorize", TokenURL: issuing.URL + "/token"}); err != nil {
		t.Fatal(err)
	}
	_, state, err := svc.BeginConnect(ctx, tenant, person.ID, "acme", "https://id.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.FinishConnect(ctx, state, "good-code", "https://id.example.test"); err == nil {
		t.Error("tokens from a token URL the provider no longer has were accepted")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.token_vault_grants WHERE tenant_id = $1`, tenant); n != 0 {
		t.Errorf("%d grants stored under the new token URL, want none", n)
	}
}

// TestProviderRegistrationValidatesItsInput checks that a provider without a
// name, client or secret is refused with the field named, and that a bad
// token URL is reported as the token URL, not the authorize URL.
func TestProviderRegistrationValidatesItsInput(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.Serve(dbtest.Principal(dbtest.User(t, tenant, tenant).ID, tenant), (&Handler{Service: NewService(dbtest.Pool(t), testCipher(t))}).Mount)
	providers := "/tenants/" + tenant.String() + "/vault/tokens/providers"
	valid := map[string]string{
		"provider": "acme", "client_id": "qeet-client", "client_secret": "secret",
		"authorize_url": "https://auth.acme.example/authorize", "token_url": "https://auth.acme.example/token",
	}
	for _, tc := range []struct{ field, value, code string }{
		{"provider", "", errs.CodeValidation},
		{"client_id", "", errs.CodeValidation},
		{"client_secret", " ", errs.CodeValidation},
		{"token_url", "http://127.0.0.1:9/token", errs.CodeTokenVaultProviderTokenURLInvalid},
		{"token_url", "not a url", errs.CodeTokenVaultProviderTokenURLInvalid},
		{"authorize_url", "ftp://auth.acme.example/authorize", errs.CodeTokenVaultProviderAuthorizeInvalid},
	} {
		body := map[string]string{}
		for k, v := range valid {
			body[k] = v
		}
		body[tc.field] = tc.value
		rec := dbtest.Do(t, admin, http.MethodPost, providers, body)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), tc.code) ||
			(tc.code == errs.CodeValidation && !strings.Contains(rec.Body.String(), `"field":"`+tc.field+`"`)) {
			t.Errorf("%s %q: %d %s, want 422 %s", tc.field, tc.value, rec.Code, rec.Body.String(), tc.code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.token_vault_providers WHERE tenant_id = $1`, tenant); n != 0 {
		t.Errorf("%d invalid providers stored", n)
	}
}

// rotatingProvider is a token endpoint that rotates refresh tokens: each is
// good once, and presenting a spent one revokes every token of the grant, as
// providers that detect reuse do. Each refresh takes a moment.
type rotatingProvider struct {
	*httptest.Server
	mu        sync.Mutex
	live      string // the refresh token that works; "" once revoked
	refreshes int
}

// count is the refreshes the provider has received.
func (p *rotatingProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshes
}

func newRotatingProvider(t *testing.T) *rotatingProvider {
	p := &rotatingProvider{live: "refresh-1"}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		time.Sleep(200 * time.Millisecond)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.refreshes++
		presented := r.PostForm.Get("refresh_token")
		if p.live == "" || presented != p.live {
			p.live = ""
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		p.live = fmt.Sprintf("refresh-%d", p.refreshes+1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":%q,"expires_in":3600}`, p.refreshes+1, p.live)
	}))
	t.Cleanup(p.Close)
	return p
}

// TestConcurrentTokenVaultRefreshKeepsTheGrant checks that two reads of a
// token due for refresh at once refresh it once, both getting the new token,
// so a provider that rotates refresh tokens doesn't see the old one reused
// and the grant keeps working.
func TestConcurrentTokenVaultRefreshKeepsTheGrant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := vaultService(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	provider := newRotatingProvider(t)
	if _, err := svc.RegisterProvider(ctx, tenant, RegisterProviderInput{Provider: "acme", ClientID: "qeet-client", ClientSecret: "secret",
		AuthorizeURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.storeGrant(ctx, svc.q, tenant, person.ID, "acme", provider.URL+"/token", "qeet-client",
		&oauthTokenResponse{AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresIn: float64(1)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	got := make([]string, 2)
	failed := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { got[i], failed[i] = svc.GetAccessToken(ctx, tenant, person.ID, "acme") })
	}
	wg.Wait()
	for i := range 2 {
		if failed[i] != nil || got[i] != "access-2" {
			t.Errorf("read %d at once: %q, %v; want the one refreshed token access-2", i, got[i], failed[i])
		}
	}
	if n := provider.count(); n != 1 {
		t.Errorf("%d refreshes reached the provider, want 1", n)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.token_vault_grants SET expires_at = NOW() WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	if token, err := svc.GetAccessToken(ctx, tenant, person.ID, "acme"); err != nil || token != "access-3" {
		t.Errorf("the next refresh: %q, %v; want the grant still working", token, err)
	}
}
