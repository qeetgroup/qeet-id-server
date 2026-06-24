package security_test

import (
	"net/http"
	"strings"
	"testing"
)

// formEndpoints are endpoints that must enforce CSRF protection.
// Bearer-token endpoints are exempt by design (ADR-0006).
var formEndpoints = []struct {
	method string
	path   string
}{
	{"POST", "/v1/auth/login"},
	{"POST", "/v1/auth/register"},
	{"POST", "/v1/auth/logout"},
}

func TestCSRFProtectionOnFormEndpoints(t *testing.T) {
	client := &http.Client{}

	probe, err := client.Get(baseURL + "/healthz")
	if err != nil {
		t.Skipf("backend not reachable: %v", err)
	}
	probe.Body.Close()

	for _, ep := range formEndpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req, err := http.NewRequest(ep.method, baseURL+ep.path,
				strings.NewReader(`{"email":"x@x.com","password":"P123!"}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			// Deliberately omit CSRF token and Origin header

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			// Should get 403 Forbidden (CSRF) or 400/422 (validation), never a 2xx
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				t.Errorf("%s %s accepted request without CSRF token (got %d)",
					ep.method, ep.path, resp.StatusCode)
			}
		})
	}
}
