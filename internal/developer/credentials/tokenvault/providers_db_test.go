//go:build integration

package tokenvault

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestProviderAtAPrivateAddressIsRefused checks that a provider whose
// endpoints are not allowed outbound destinations is not registered.
func TestProviderAtAPrivateAddressIsRefused(t *testing.T) {
	strict := NewService(dbtest.Pool(t), testCipher(t))
	if _, err := strict.RegisterProvider(dbtest.Context(t), dbtest.Organization(t), RegisterProviderInput{
		Provider: "internal", ClientID: "c", ClientSecret: "s", AuthorizeURL: "http://127.0.0.1:9/authorize", TokenURL: "http://127.0.0.1:9/token",
	}); err == nil {
		t.Error("a provider at a private address was registered")
	}
}

// TestTokenVaultEndpointsCannotChangeUnderLiveGrants checks that while anyone
// is connected through a provider its token URL, authorize URL and client
// can't change, nor can deleting and adding it again hand its grants to new
// endpoints, so a refresh token goes only to the endpoint it came from; the
// secret and scopes still change, and an unused provider changes freely.
func TestTokenVaultEndpointsCannotChangeUnderLiveGrants(t *testing.T) {
	svc := vaultService(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	admin := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), (&Handler{Service: svc}).Mount)
	providers := "/organizations/" + organization.String() + "/vault/tokens/providers"
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
	connected(t, organization, person.ID, "acme")
	for key, value := range map[string]string{
		"token_url":     "https://collector.example/token",
		"authorize_url": "https://collector.example/authorize",
		"client_id":     "other-client",
	} {
		if rec := dbtest.Do(t, admin, http.MethodPost, providers, with(key, value)); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), CodeProviderInUse) {
			t.Errorf("change %s under a live grant: %d %s, want 409 %s", key, rec.Code, rec.Body.String(), CodeProviderInUse)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.token_vault_providers WHERE organization_id = $1 AND token_url = 'https://auth.acme.example/token' AND client_id = 'qeet-client'`, organization); n != 1 {
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
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.token_vault_grants WHERE organization_id = $1 AND provider = 'acme'`, organization); n != 0 {
		t.Errorf("%d grants kept by a deleted provider, want none", n)
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, with("token_url", "https://collector.example/token")); rec.Code != http.StatusCreated {
		t.Errorf("register again, with nobody connected, at another token URL: %d %s, want 201", rec.Code, rec.Body.String())
	}
	connected(t, organization, person.ID, "orphaned")
	if rec := dbtest.Do(t, admin, http.MethodPost, providers, with("provider", "orphaned")); rec.Code != http.StatusConflict {
		t.Errorf("register a provider whose name still has grants: %d %s, want 409", rec.Code, rec.Body.String())
	}
}

// TestProviderRegistrationValidatesItsInput checks that a provider without a
// name, client or secret is refused with the field named, and that a bad
// token URL is reported as the token URL, not the authorize URL.
func TestProviderRegistrationValidatesItsInput(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), (&Handler{Service: NewService(dbtest.Pool(t), testCipher(t))}).Mount)
	providers := "/organizations/" + organization.String() + "/vault/tokens/providers"
	valid := map[string]string{
		"provider": "acme", "client_id": "qeet-client", "client_secret": "secret",
		"authorize_url": "https://auth.acme.example/authorize", "token_url": "https://auth.acme.example/token",
	}
	for _, tc := range []struct{ field, value, code string }{
		{"provider", "", errs.CodeValidation},
		{"client_id", "", errs.CodeValidation},
		{"client_secret", " ", errs.CodeValidation},
		{"token_url", "http://127.0.0.1:9/token", CodeProviderTokenURLInvalid},
		{"token_url", "not a url", CodeProviderTokenURLInvalid},
		{"authorize_url", "ftp://auth.acme.example/authorize", CodeProviderAuthorizeInvalid},
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
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.token_vault_providers WHERE organization_id = $1`, organization); n != 0 {
		t.Errorf("%d invalid providers stored", n)
	}
}
