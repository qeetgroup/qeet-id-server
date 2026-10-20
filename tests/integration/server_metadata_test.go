//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
)

// TestAnOAuthOnlyClientCanConfigureItself pins the machine-client discovery
// chain: the protected-resource document (RFC 9728) names an authorization
// server whose RFC 8414 metadata exists, agrees with the OpenID configuration,
// and the resource document emits the scopes its schema declares.
func TestAnOAuthOnlyClientCanConfigureItself(t *testing.T) {
	requireDB(t)
	svc := oidc.NewService(testPool, mustIssuer())
	r := chi.NewRouter()
	(&oidc.Handler{Service: svc}).MountPublic(r)
	fetch := func(t *testing.T, path string) map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, rr.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return doc
	}

	resource := fetch(t, "/.well-known/oauth-protected-resource")
	if scopes, _ := resource["scopes_supported"].([]any); len(scopes) == 0 {
		t.Fatalf("protected-resource document has no scopes_supported: %+v", resource)
	}
	servers, _ := resource["authorization_servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("authorization_servers = %v", servers)
	}
	as, err := url.Parse(servers[0].(string))
	if err != nil {
		t.Fatal(err)
	}
	// RFC 8414 §3: the metadata lives at the issuer's well-known path.
	meta := fetch(t, as.Path+"/.well-known/oauth-authorization-server")
	oidcDoc := fetch(t, "/.well-known/openid-configuration")
	if meta["issuer"] != servers[0] {
		t.Fatalf("authorization server metadata issuer %v, want %v", meta["issuer"], servers[0])
	}
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint",
		"introspection_endpoint", "response_types_supported", "grant_types_supported", "code_challenge_methods_supported"} {
		a, _ := json.Marshal(meta[field])
		b, _ := json.Marshal(oidcDoc[field])
		if meta[field] == nil || string(a) != string(b) {
			t.Fatalf("%s: OAuth metadata %s, OpenID configuration %s; want both, equal", field, a, b)
		}
	}
	if _, ok := oidcDoc["protected_resource_metadata"]; ok {
		t.Fatal("the OpenID configuration still carries the invented protected_resource_metadata key")
	}
	if methods, _ := meta["code_challenge_methods_supported"].([]any); !slices.Contains(methods, any("S256")) {
		t.Fatalf("code_challenge_methods_supported = %v", methods)
	}
}
