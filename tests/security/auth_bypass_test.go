package security_test

import (
	"net/http"
	"testing"
)

// protectedEndpoints lists endpoints that must reject unauthenticated requests.
//
// QID-20: this list was stale — it used paths that don't match the real router
// (e.g. /v1/organizations, /v1/roles, /v1/audit/events, /v1/compliance/export,
// /v1/agents), so unauthenticated probes hit chi's NotFound/MethodNotAllowed
// (404/405) instead of the auth gate. The test then "passed" only because Go's
// test cache served a stale result (it can't see the live backend it probes),
// so this security regression check was vacuously green while verifying nothing.
// These are now the real authed-group GET routes; the tenant-scoped ones use a
// zero-UUID placeholder because RequireAuth runs (and 401s) before any tenant
// match, so the id value is irrelevant to the auth check.
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

	// Verify backend is up
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
