//go:build integration

package tokenvault

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
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

// exchanges counts the token requests the provider received.
func (p *oauthProvider) exchanges() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.forms)
}

// vaultService returns the vault, allowed to call loopback providers.
func vaultService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(dbtest.Context(t), dbtest.Pool(t), secret.StaticKeyProvider{Key: []byte("0123456789abcdef0123456789abcdef")}, egress.DevelopmentPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// signedIn is p as a person's own session holding scopes.
func signedIn(p *httpx.Principal, scopes ...string) *httpx.Principal {
	sid := uuid.New()
	p.SessionID, p.Scopes = &sid, scopes
	return p
}

// TestConnectedAccountLifecycle checks that an organisation registers a
// provider without its secret ever being returned, a person connects an
// account once per ceremony, its token is refreshed when due and given only to
// that person signed in with the scope, and it can be disconnected.
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

	connect := func() string {
		t.Helper()
		rec := dbtest.Do(t, asPerson, http.MethodGet, "/vault/tokens/acme/connect", nil)
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
		return q.Get("state")
	}
	state := connect()
	if rec := dbtest.Do(t, public, http.MethodGet, "/vault/tokens/callback?state="+state+"&code=good-code", nil); rec.Code != http.StatusOK {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, public, http.MethodGet, "/vault/tokens/callback?state="+state+"&code=good-code", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("the same callback twice: %d, want refused", rec.Code)
	}
	for name, query := range map[string]string{
		"refused at the provider": "error=access_denied",
		"without a code":          "state=" + connect(),
		"with an unknown state":   "state=forged&code=good-code",
		"with a bad code":         "state=" + connect() + "&code=bad-code",
	} {
		if rec := dbtest.Do(t, public, http.MethodGet, "/vault/tokens/callback?"+query, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("a callback %s: %d, want refused", name, rec.Code)
		}
	}
	expired := connect()
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.token_vault_connect_states SET expires_at = now() - interval '1 minute' WHERE state = $1`, expired); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, public, http.MethodGet, "/vault/tokens/callback?state="+expired+"&code=good-code", nil); !strings.Contains(rec.Body.String(), "expired") {
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
		if _, err := svc.BeginConnect(ctx, tenant, person.ID, "legacy", "https://id.example.test"); err != nil {
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

	strict, err := NewService(ctx, pool, secret.StaticKeyProvider{Key: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.RegisterProvider(ctx, tenant, RegisterProviderInput{
		Provider: "internal", ClientID: "c", ClientSecret: "s", AuthorizeURL: "http://127.0.0.1:9/authorize", TokenURL: "http://127.0.0.1:9/token",
	}); err == nil {
		t.Error("a provider at a private address was registered")
	}
}
