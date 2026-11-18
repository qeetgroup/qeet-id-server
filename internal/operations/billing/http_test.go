package billing

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestSandboxPageCanSubmitItsForm checks that the mock checkout page, served behind the API's
// security headers, carries its own policy: its form may post to this server and be redirected to
// the success address, and its inline style applies. The API's own policy forbids every form.
func TestSandboxPageCanSubmitItsForm(t *testing.T) {
	h := &Handler{Service: &Service{payments: NewPayments("", "", "", "", "").WithSandbox("http://localhost:4001", "secret")}}
	page := httpx.SecurityHeaders(false)(http.HandlerFunc(h.sandboxCheckoutPage))
	w := httptest.NewRecorder()
	page.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/v1/billing/sandbox/checkout?ref=r1&plan=Pro&amount=9900&currency=USD&success_url=http://localhost:3002/ok&cancel_url=http://localhost:3002/no", nil))
	csp := w.Header().Get("Content-Security-Policy")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/v1/billing/sandbox/pay"`) {
		t.Fatalf("page: %d %s", w.Code, w.Body.String())
	}
	for _, want := range []string{"form-action 'self' http://localhost:3002;", "style-src 'unsafe-inline'", "default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy %q, want %s", csp, want)
		}
	}
}

// TestSandboxPagePolicyNamesOnlyAPlainOrigin checks that a success address whose host could carry
// more policy text is left out of the header: the form may then post only to this server.
func TestSandboxPagePolicyNamesOnlyAPlainOrigin(t *testing.T) {
	for _, successURL := range []string{"http://a;script-src'unsafe-inline'/ok", "https://x*/ok", "not a url"} {
		if csp := sandboxPageCSP(successURL); !strings.Contains(csp, "form-action 'self';") {
			t.Errorf("%s: policy %q, want form-action 'self' only", successURL, csp)
		}
	}
}
