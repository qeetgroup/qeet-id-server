//go:build integration

package tokenvault

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// system is the actor of a test's own calls.
var system = audit.Actor{Type: "system"}

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

// TestConnectedAccountLifecycle checks that an organization registers a
// provider without its secret ever being returned, a person connects an
// account once per ceremony, only in the browser that began it and with its
// PKCE verifier, its token is refreshed when due and given only to that person
// signed in with the scope, and it can be disconnected.
func TestConnectedAccountLifecycle(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := vaultService(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	provider := newOAuthProvider(t)
	vault := &Handler{Service: svc, PublicBaseURL: "https://id.example.test"}
	asPerson := dbtest.Serve(signedIn(dbtest.Principal(person.ID, organization), "vault:acme"), vault.Mount)
	public := chi.NewRouter()
	vault.MountPublic(public)
	providers := "/organizations/" + organization.String() + "/vault/tokens/providers"

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
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.token_vault_connect_states SET expires_at = now() - interval '1 minute' WHERE state = $1`, expired); err != nil {
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
		"an API key":           {UserID: &person.ID, OrganizationID: &organization, ActorType: "api_key", Subject: "key-1", Scopes: []string{"vault:read"}},
		"an application":       {UserID: &person.ID, OrganizationID: &organization, ActorType: "user", ClientID: "app", SessionID: &person.ID, Scopes: []string{"vault:read"}},
		"without a session":    {UserID: &person.ID, OrganizationID: &organization, ActorType: "user", Scopes: []string{"vault:read"}},
		"without the scope":    signedIn(dbtest.Principal(person.ID, organization), "vault:other"),
		"another person":       signedIn(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), "vault:read"),
		"another organization": signedIn(dbtest.Principal(person.ID, other), "vault:read"),
	} {
		if code, body := accessToken(dbtest.Serve(p, vault.Mount)); code == http.StatusOK || strings.Contains(body, "access-2") {
			t.Errorf("%s read the token: %d %s", name, code, body)
		}
	}
	var refused int
	if err := dbtest.Pool(t).QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'vault.tokens.access_refused'`, organization).Scan(&refused); err != nil || refused != 3 {
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
	if rec := dbtest.Do(t, asPerson, http.MethodGet, "/vault/tokens/acme/connect", nil); !strings.Contains(rec.Body.String(), CodeProviderNotFound) {
		t.Errorf("connect to a deleted provider: %d %s", rec.Code, rec.Body.String())
	}
}

// connected stores a grant of person's for provider, as a finished connect
// ceremony would.
func connected(t *testing.T, organization, person uuid.UUID, provider string) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO organization.token_vault_grants (organization_id, user_id, provider, access_token_ct, access_token_nonce, refresh_token_ct, refresh_token_nonce)
		VALUES ($1, $2, $3, 'ct', 'nonce', 'ct', 'nonce')`, organization, person, provider); err != nil {
		t.Fatal(err)
	}
}
