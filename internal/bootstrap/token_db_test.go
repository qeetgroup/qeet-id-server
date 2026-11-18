//go:build integration

package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/developer/agent"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestTokenEndpointServesEveryClient checks the client_credentials grant at
// the one token endpoint, through the production router: a service principal
// and an agent each get their own token, its secret in the form or Basic; a
// wrong secret or an unknown id is invalid_client, described alike; a disabled
// principal, a suspended agent and an application are unauthorized_client.
// TestOneTokenEndpoint checks the paths it replaced are gone.
func TestTokenEndpointServesEveryClient(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	issuer := dbtest.Issuer(t)
	principals, agents := principal.NewService(pool, issuer), agent.NewService(pool, issuer)
	svc := oidc.NewService(pool, issuer)
	svc.SetMachineClients(principals, agents)
	deps := routeInventoryDeps(t)
	deps.OIDC = &oidc.Handler{Service: svc}
	router := NewRouter(deps)

	organization := dbtest.Organization(t)
	system := audit.Actor{Type: "system"}
	p, principalSecret, err := principals.Create(ctx, principal.CreateInput{OrganizationID: organization, Name: "Reporting", Scopes: []string{"user.read"}}, system)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	app, appSecret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{OrganizationID: organization, Name: "Web", RedirectURIs: []string{"https://app.example.test/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := agents.Create(ctx, organization, "triage-bot", []string{"audit.read"}, 120, dbtest.User(t, organization, organization).ID, system)
	if err != nil {
		t.Fatal(err)
	}

	post := func(path string, form url.Values, user, pass string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	clientCredentials := url.Values{"grant_type": {"client_credentials"}}
	inForm := func(id, secret string) url.Values {
		return url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
	}
	// refused checks an RFC 6749 §5.2 answer, and that it isn't cached.
	refused := func(name string, rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != status || body["error"] != code {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), status, code)
		}
		if code == "invalid_client" && body["error_description"] != errs.ErrOIDCClientAuthFailed.Message {
			t.Errorf("%s: described %q, want %q", name, body["error_description"], errs.ErrOIDCClientAuthFailed.Message)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", name, rec.Header().Get("Cache-Control"))
		}
	}
	// issued checks a token answer and returns the token's claims.
	issued := func(name string, rec *httptest.ResponseRecorder, lifetime time.Duration) map[string]any {
		t.Helper()
		var body struct {
			AccessToken string    `json:"access_token"`
			TokenType   string    `json:"token_type"`
			ExpiresIn   int       `json:"expires_in"`
			ExpiresAt   time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || body.TokenType != "Bearer" ||
			body.ExpiresIn != int(lifetime.Seconds()) || body.ExpiresAt.Before(time.Now().Add(lifetime-time.Minute)) {
			t.Fatalf("%s: %d %s, want a Bearer token for %v", name, rec.Code, rec.Body.String(), lifetime)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", name, rec.Header().Get("Cache-Control"))
		}
		claims, err := issuer.VerifySigned(body.AccessToken)
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		return claims
	}

	pid, aid := p.ID.String(), a.ID.String()
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"a service principal by Basic":    post("/v1/oauth/token", clientCredentials, pid, principalSecret),
		"a service principal by the form": post("/v1/oauth/token", inForm(pid, principalSecret), "", ""),
	} {
		claims := issued(name, rec, issuer.AccessTTL())
		if claims["sub"] != pid || claims["actor_type"] != "service" || claims["scope"] != "user.read" || claims["agent_id"] != nil {
			t.Errorf("%s: claims %v, want the principal's own", name, claims)
		}
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"an agent by Basic":    post("/v1/oauth/token", clientCredentials, aid, a.Secret),
		"an agent by the form": post("/v1/oauth/token", inForm(aid, a.Secret), "", ""),
	} {
		claims := issued(name, rec, 2*time.Minute)
		if claims["sub"] != aid || claims["actor_type"] != "agent" || claims["agent_id"] != aid || claims["scope"] != "audit.read" {
			t.Errorf("%s: claims %v, want the agent's own", name, claims)
		}
	}

	refused("a principal's wrong secret", post("/v1/oauth/token", clientCredentials, pid, "wrong"), http.StatusUnauthorized, "invalid_client")
	refused("an agent's wrong secret", post("/v1/oauth/token", inForm(aid, "wrong"), "", ""), http.StatusUnauthorized, "invalid_client")
	refused("an unknown id", post("/v1/oauth/token", clientCredentials, uuid.NewString(), principalSecret), http.StatusUnauthorized, "invalid_client")
	refused("no credentials", post("/v1/oauth/token", clientCredentials, "", ""), http.StatusUnauthorized, "invalid_client")
	refused("an application's wrong secret", post("/v1/oauth/token", clientCredentials, app.ClientID, "wrong"), http.StatusUnauthorized, "invalid_client")
	refused("an application", post("/v1/oauth/token", clientCredentials, app.ClientID, appSecret), http.StatusBadRequest, "unauthorized_client")
	withResource := inForm(pid, principalSecret)
	withResource.Set("resource", "https://api.example.test")
	refused("a resource", post("/v1/oauth/token", withResource, "", ""), http.StatusBadRequest, "invalid_target")

	if _, err := pool.Exec(ctx, `UPDATE auth.service_principals SET disabled_at = NOW() WHERE id = $1 AND organization_id = $2`, p.ID, organization); err != nil {
		t.Fatal(err)
	}
	refused("a disabled principal", post("/v1/oauth/token", clientCredentials, pid, principalSecret), http.StatusBadRequest, "unauthorized_client")
	if _, err := agents.Transition(ctx, a.ID, organization, "suspended", system); err != nil {
		t.Fatal(err)
	}
	refused("a suspended agent", post("/v1/oauth/token", clientCredentials, aid, a.Secret), http.StatusBadRequest, "unauthorized_client")
}
