package security_test

import (
	"net/http"
	"testing"
)

// protectedEndpoints lists the real authed-group GET routes that must reject
// unauthenticated requests. They must match the live router exactly (QID-20: a
// stale list hit chi's 404/405 instead of the auth gate, passing vacuously).
// Tenant-scoped paths use a zero-UUID placeholder since RequireAuth 401s before
// any tenant match, so the id value is irrelevant.
var protectedEndpoints = []string{
	"/v1/users",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/roles",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/audit",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/api-keys",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/webhooks",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/agents",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/secrets",
	"/v1/tenants/00000000-0000-0000-0000-000000000000/gdpr/export",
}

func TestProtectedEndpointsRequireAuth(t *testing.T) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	probe, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Skipf("backend not reachable: %v", err)
	}
	probe.Body.Close()

	for _, path := range protectedEndpoints {
		t.Run(path, func(t *testing.T) {
			resp, err := client.Get(baseURL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Errorf("GET %s returned %d; want 401 or 403", path, resp.StatusCode)
			}
		})
	}
}
