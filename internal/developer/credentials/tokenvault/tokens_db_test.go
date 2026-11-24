//go:build integration

package tokenvault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

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
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	provider := newRotatingProvider(t)
	if _, err := svc.RegisterProvider(ctx, organization, RegisterProviderInput{Provider: "acme", ClientID: "qeet-client", ClientSecret: "secret",
		AuthorizeURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.storeGrant(ctx, svc.q, organization, person.ID, "acme", provider.URL+"/token", "qeet-client",
		&oauthTokenResponse{AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresIn: float64(1)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	got := make([]string, 2)
	failed := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { got[i], failed[i] = svc.GetAccessToken(ctx, organization, person.ID, "acme", system) })
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
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.token_vault_grants SET expires_at = NOW() WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	if token, err := svc.GetAccessToken(ctx, organization, person.ID, "acme", system); err != nil || token != "access-3" {
		t.Errorf("the next refresh: %q, %v; want the grant still working", token, err)
	}
}

// refuseAudit makes the database refuse organization's audit rows of action
// until t ends, as a failing audit write would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	ctx, owner := dbtest.Context(t), dbtest.Owner(t)
	name := "refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, sql := range []string{
		`CREATE FUNCTION audit.` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`,
		fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON audit.events FOR EACH ROW
			WHEN (NEW.organization_id = '%s' AND NEW.action = '%s') EXECUTE FUNCTION audit.%s()`, name, organization, action, name),
	} {
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatalf("refuse %s: %v", action, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit.events; DROP FUNCTION audit.`+name+`()`)
	})
}

// TestTokenReadIsAuditedOrRefused checks that a person's read of a connected
// account's token is audited as theirs and refused, with no token, when its
// audit row can't be written; and that a credential's refused read stays
// refused when its own record can't be written.
func TestTokenReadIsAuditedOrRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := vaultService(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	provider := newRotatingProvider(t)
	if _, err := svc.RegisterProvider(ctx, organization, RegisterProviderInput{Provider: "acme", ClientID: "qeet-client", ClientSecret: "secret",
		AuthorizeURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.storeGrant(ctx, svc.q, organization, person.ID, "acme", provider.URL+"/token", "qeet-client",
		&oauthTokenResponse{AccessToken: "access-live", ExpiresIn: float64(3600)}); err != nil {
		t.Fatal(err)
	}
	vault := &Handler{Service: svc}
	asPerson := dbtest.Serve(signedIn(dbtest.Principal(person.ID, organization), "vault:acme"), vault.Mount)
	asKey := dbtest.Serve(&httpx.Principal{UserID: &person.ID, OrganizationID: &organization, ActorType: "api_key", Subject: "key-1",
		Scopes: []string{"vault:read"}}, vault.Mount)
	read := func(h http.Handler) *httptest.ResponseRecorder {
		return dbtest.Do(t, h, http.MethodGet, "/vault/tokens/acme/access-token", nil)
	}

	if rec := read(asPerson); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "access-live") {
		t.Fatalf("read: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'vault.tokens.accessed'
		AND actor_user_id = $2 AND actor_type = 'user' AND metadata->>'provider' = 'acme'`, organization, person.ID); n != 1 {
		t.Errorf("a read: %d audit rows as the person, want 1", n)
	}

	refuseAudit(t, organization, "vault.tokens.accessed")
	refuseAudit(t, organization, "vault.tokens.access_refused")
	if rec := read(asPerson); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "access-live") {
		t.Errorf("a read with its audit refused: %d %s; want refused with no token", rec.Code, rec.Body.String())
	}
	if rec := read(asKey); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "tokenvault.people_only") {
		t.Errorf("a key's read with its record refused: %d %s; want it refused as before", rec.Code, rec.Body.String())
	}
}
