package security_test

import (
	"net/http"
	"testing"
)

// protectedEndpoints lists endpoints that must reject unauthenticated requests.
var protectedEndpoints = []string{
	"/v1/users",
	"/v1/users/me",
	"/v1/organizations",
	"/v1/api-keys",
	"/v1/roles",
	"/v1/audit/events",
	"/v1/compliance/export",
	"/v1/webhooks",
	"/v1/agents",
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
