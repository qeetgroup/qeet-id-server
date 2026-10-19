//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestAPIKeysActOnlyForTheirCreator pins who an API key can be: its creator,
// or no one. A key can't be made to act for a colleague or for someone in
// another organization, no key is handed a person's connected-app token, and
// every vault access by a key is recorded as that key.
func TestAPIKeysActOnlyForTheirCreator(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	keys := apikey.NewService(testPool)

	home := createTenant(t, ctx, uniqueSlug("keys-home"))
	other := createTenant(t, ctx, uniqueSlug("keys-other"))
	dev := createUserInTenant(t, ctx, home)
	addTenantMembership(t, ctx, dev, home)
	cara := createUserInTenant(t, ctx, home)
	addTenantMembership(t, ctx, cara, home)
	outsider := createUserInTenant(t, ctx, other)
	addTenantMembership(t, ctx, outsider, other)
	byDev := audit.Actor{Type: "user", UserID: &dev}

	countKeys := func(t *testing.T, name string) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.api_keys WHERE name = $1`, name).Scan(&n); err != nil {
			t.Fatalf("count keys: %v", err)
		}
		return n
	}
	audited := func(t *testing.T, action string, resource uuid.UUID) (actor *uuid.UUID, actorType string, md map[string]any) {
		t.Helper()
		if err := testPool.QueryRow(ctx,
			`SELECT actor_user_id, actor_type, metadata FROM audit.events
			  WHERE tenant_id = $1 AND action = $2 AND resource_id = $3 ORDER BY created_at DESC LIMIT 1`,
			home, action, resource).Scan(&actor, &actorType, &md); err != nil {
			t.Fatalf("no %s audit row for %s: %v", action, resource, err)
		}
		return actor, actorType, md
	}

	for _, c := range []struct {
		name string
		user uuid.UUID
	}{
		{"a colleague", cara},
		{"someone in another organization", outsider},
	} {
		t.Run("a key acting for "+c.name+" is refused", func(t *testing.T) {
			name := uniqueSlug("bot")
			user := c.user
			_, _, err := keys.Create(ctx, apikey.CreateInput{
				TenantID: home, UserID: &user, Name: name, Scopes: []string{"vault:read"}, Actor: byDev,
			})
			if !errors.Is(err, errs.ErrAPIKeyUserNotSelf) {
				t.Fatalf("err = %v, want %v", err, errs.ErrAPIKeyUserNotSelf)
			}
			if n := countKeys(t, name); n != 0 {
				t.Fatalf("a refused key was written (%d rows)", n)
			}
		})
	}

	var selfKey *apikey.Key
	t.Run("a key acting for its creator is created and audited", func(t *testing.T) {
		k, raw, err := keys.Create(ctx, apikey.CreateInput{
			TenantID: home, UserID: &dev, Name: uniqueSlug("mine"), Actor: byDev,
		})
		if err != nil || raw == "" {
			t.Fatalf("create: %v", err)
		}
		if k.UserID == nil || *k.UserID != dev {
			t.Fatalf("key user = %v, want the creator", k.UserID)
		}
		actor, _, md := audited(t, "apikey.created", k.ID)
		if actor == nil || *actor != dev || md["user_id"] != dev.String() {
			t.Fatalf("apikey.created audit: actor %v, metadata %v", actor, md)
		}
		selfKey = k
	})

	t.Run("a key acting for no one is created as before", func(t *testing.T) {
		k, _, err := keys.Create(ctx, apikey.CreateInput{TenantID: home, Name: uniqueSlug("ci"), Actor: byDev})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if k.UserID != nil {
			t.Fatalf("key user = %v, want none", k.UserID)
		}
	})

	t.Run("revoking a key is audited", func(t *testing.T) {
		if selfKey == nil {
			t.Skip("no key to revoke")
		}
		if err := keys.Revoke(ctx, home, selfKey.ID, byDev); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if actor, _, _ := audited(t, "apikey.revoked", selfKey.ID); actor == nil || *actor != dev {
			t.Fatalf("apikey.revoked audit actor = %v, want the revoker", actor)
		}
	})

	// Cara connects a third-party account through the token vault.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "cara-chat-token", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer mock.Close()
	kp := secret.StaticKeyProvider{Key: []byte("01234567890123456789012345678901")}
	vault, err := tokenvault.NewService(ctx, testPool, kp, egress.DevelopmentPolicy())
	if err != nil {
		t.Fatalf("token vault: %v", err)
	}
	if _, err := vault.RegisterProvider(ctx, home, tokenvault.RegisterProviderInput{
		Provider: "chat", ClientID: "cid", ClientSecret: "csecret",
		AuthorizeURL: mock.URL + "/authorize", TokenURL: mock.URL + "/token", Scopes: "read",
	}); err != nil {
		t.Fatalf("register provider: %v", err)
	}
	authorizeURL, err := vault.BeginConnect(ctx, home, cara, "chat", "https://id.example.com")
	if err != nil {
		t.Fatalf("begin connect: %v", err)
	}
	u, _ := url.Parse(authorizeURL)
	if err := vault.FinishConnect(ctx, u.Query().Get("state"), "code", "https://id.example.com"); err != nil {
		t.Fatalf("finish connect: %v", err)
	}
	vaultRoutes := chi.NewRouter()
	(&tokenvault.Handler{Service: vault}).Mount(vaultRoutes)
	call := func(routes http.Handler, p *httpx.Principal, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		routes.ServeHTTP(rec, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
		return rec
	}

	t.Run("a key naming a colleague is refused that colleague's connected-app token", func(t *testing.T) {
		keyID := uuid.New() // a key written before creation checked its user
		rec := call(vaultRoutes, &httpx.Principal{
			ActorType: "api_key", Subject: keyID.String(), TenantID: &home, UserID: &cara, Scopes: []string{"vault:read"},
		}, "/vault/tokens/chat/access-token")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body %s; want 403", rec.Code, rec.Body.String())
		}
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'vault.tokens.access_refused'
			    AND actor_type = 'api_key' AND metadata->>'credential_id' = $2`, home, keyID.String()).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if n != 1 {
			t.Fatal("the refused key was not recorded as that key")
		}
	})

	t.Run("the person who connected the account still gets their own token", func(t *testing.T) {
		session := uuid.New()
		rec := call(vaultRoutes, &httpx.Principal{
			ActorType: "user", TenantID: &home, UserID: &cara, SessionID: &session, Scopes: []string{"vault:chat"},
		}, "/vault/tokens/chat/access-token")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s; want 200", rec.Code, rec.Body.String())
		}
	})

	t.Run("the review script lists keys acting for people, with their organization status", func(t *testing.T) {
		check := readRepoFile(t, "tools", "scripts", "api-keys-acting-for-people.sql")
		// Keys written before creation checked its user: one for a colleague,
		// one for someone in another organization.
		forCara, forOutsider := uuid.New(), uuid.New()
		for _, k := range []struct{ id, user uuid.UUID }{{forCara, cara}, {forOutsider, outsider}} {
			if _, err := testPool.Exec(ctx,
				`INSERT INTO auth.api_keys (id, tenant_id, user_id, name, prefix, key_hash, scopes)
				 VALUES ($1, $2, $3, $4, $5, 'x', '{}')`,
				k.id, home, k.user, uniqueSlug("old"), uniqueSlug("p")); err != nil {
				t.Fatalf("seed old key: %v", err)
			}
		}
		rows, err := testPool.Query(ctx, check)
		if err != nil {
			t.Fatalf("run script: %v", err)
		}
		defer rows.Close()
		member := map[uuid.UUID]bool{}
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			id, _ := vals[1].([16]byte)
			member[uuid.UUID(id)] = vals[6].(bool)
		}
		if got, ok := member[forCara]; !ok || !got {
			t.Fatalf("the colleague's key is missing or not marked a member: %v", member)
		}
		if got, ok := member[forOutsider]; !ok || got {
			t.Fatalf("the outsider's key is missing or marked a member: %v", member)
		}
	})

	t.Run("a key reading a vault secret is recorded as that key", func(t *testing.T) {
		secrets, err := secret.NewService(ctx, testPool, kp)
		if err != nil {
			t.Fatalf("secrets: %v", err)
		}
		name := uniqueSlug("deploy-token")
		s, err := secrets.Create(ctx, home, name, "", "s3cr3t")
		if err != nil {
			t.Fatalf("create secret: %v", err)
		}
		routes := chi.NewRouter()
		(&secret.Handler{Service: secrets}).Mount(routes)
		keyID := uuid.New()
		rec := call(routes, &httpx.Principal{
			ActorType: "api_key", Subject: keyID.String(), TenantID: &home, UserID: &dev, Scopes: []string{"vault:" + name},
		}, "/vault/"+name)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s; want 200", rec.Code, rec.Body.String())
		}
		_, actorType, md := audited(t, "vault.accessed", s.ID)
		if actorType != "api_key" || md["credential_id"] != keyID.String() {
			t.Fatalf("vault.accessed audit: actor_type %q, metadata %v", actorType, md)
		}
	})
}
