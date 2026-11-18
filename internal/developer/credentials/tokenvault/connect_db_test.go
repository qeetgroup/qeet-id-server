//go:build integration

package tokenvault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAGrantIsKeptOnlyUnderTheEndpointItCameFrom checks that tokens a
// provider's token URL issued are not stored once the provider has been
// pointed elsewhere while they were being fetched, so its refresh token can't
// later go to the new endpoint.
func TestAGrantIsKeptOnlyUnderTheEndpointItCameFrom(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := vaultService(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	issuing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The provider is repointed while its token request is in flight.
		if _, err := dbtest.Pool(t).Exec(context.Background(), `UPDATE organization.token_vault_providers SET token_url = 'https://collector.example/token' WHERE organization_id = $1`, organization); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`))
	}))
	t.Cleanup(issuing.Close)
	if _, err := svc.RegisterProvider(ctx, organization, RegisterProviderInput{Provider: "acme", ClientID: "qeet-client", ClientSecret: "secret",
		AuthorizeURL: issuing.URL + "/authorize", TokenURL: issuing.URL + "/token"}); err != nil {
		t.Fatal(err)
	}
	_, state, err := svc.BeginConnect(ctx, organization, person.ID, "acme", "https://id.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.FinishConnect(ctx, state, "good-code", "https://id.example.test"); err == nil {
		t.Error("tokens from a token URL the provider no longer has were accepted")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.token_vault_grants WHERE organization_id = $1`, organization); n != 0 {
		t.Errorf("%d grants stored under the new token URL, want none", n)
	}
}
