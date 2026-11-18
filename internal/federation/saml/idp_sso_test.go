package saml

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestPostFormRunsUnderItsPolicy checks that the HTTP-POST binding page allows
// its own submit script by hash, and has no inline handler the policy blocks.
func TestPostFormRunsUnderItsPolicy(t *testing.T) {
	rec := httptest.NewRecorder()
	writePostForm(rec, "https://sp.example.com/acs", "PHJlc3BvbnNlLz4=", "state")
	sum := sha256.Sum256([]byte(autoSubmit))
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Errorf("Content-Security-Policy %q does not allow the submit script", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<script>"+autoSubmit+"</script>") || strings.Contains(body, "onload=") {
		t.Errorf("page does not submit through the allowed script: %s", body)
	}
	if !strings.Contains(body, `action="https://sp.example.com/acs"`) {
		t.Errorf("form does not post to the ACS URL: %s", body)
	}
}

// TestSSOReturnURLCarriesThePostedRequest checks that the return URL for a
// POST-binding request is a GET carrying the same AuthnRequest in the Redirect
// binding's encoding, and its RelayState; a GET returns to itself.
func TestSSOReturnURLCarriesThePostedRequest(t *testing.T) {
	const base = "https://api.id.qeet.in"
	path := "/saml/idp/" + uuid.NewString() + "/sso"
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_post-1">` +
		`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer></samlp:AuthnRequest>`
	post := func(form url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return r
	}

	ret, err := ssoReturnURL(base, post(url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(raw))}, "RelayState": {"state-1"},
	}))
	if err != nil {
		t.Fatalf("ssoReturnURL: %v", err)
	}
	u, err := url.Parse(ret)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != base+path {
		t.Fatalf("return URL %q, want %s%s", ret, base, path)
	}
	ar, err := decodeAuthnRequest(u.Query().Get("SAMLRequest"), http.MethodGet)
	if err != nil || ar.ID != "_post-1" || ar.Issuer != "https://sp.example.com" {
		t.Errorf("returned SAMLRequest decodes to %+v, %v; want _post-1 from https://sp.example.com", ar, err)
	}
	if got := u.Query().Get("RelayState"); got != "state-1" {
		t.Errorf("RelayState %q, want state-1", got)
	}

	ret, err = ssoReturnURL(base, post(url.Values{"sp": {"https://sp.example.com"}}))
	if err != nil || ret != base+path+"?sp="+url.QueryEscape("https://sp.example.com") {
		t.Errorf("IdP-initiated return URL %q, %v", ret, err)
	}
	tooLarge := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", maxInflatedAuthnRequest+1)))
	if _, err := ssoReturnURL(base, post(url.Values{"SAMLRequest": {tooLarge}})); !errors.Is(err, ErrAuthnRequestInvalid) {
		t.Errorf("oversized request: %v, want ErrSAMLAuthnRequestInvalid", err)
	}
	get := httptest.NewRequest(http.MethodGet, path+"?SAMLRequest=abc&RelayState=s", nil)
	if ret, err := ssoReturnURL(base, get); err != nil || ret != base+path+"?SAMLRequest=abc&RelayState=s" {
		t.Errorf("GET return URL %q, %v", ret, err)
	}
}

// TestSSOErrorsShowABrowserAPage checks that the SSO endpoint answers a
// browser with a page saying why it can't sign in, escaped and scriptless,
// and anything else with the JSON error.
func TestSSOErrorsShowABrowserAPage(t *testing.T) {
	err := ErrNameIDUnavailable.WithMessage("No <script> for you")
	page := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/saml/idp/x/sso", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	writeSSOError(page, r, err)
	body := page.Body.String()
	if page.Code != http.StatusForbidden || !strings.HasPrefix(page.Header().Get("Content-Type"), "text/html") ||
		page.Header().Get("Content-Security-Policy") != errorPageCSP {
		t.Errorf("page %d %q %q, want 403 HTML under the page policy", page.Code, page.Header().Get("Content-Type"), page.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(body, "No &lt;script&gt; for you") || !strings.Contains(body, CodeNameIDUnavailable) || strings.Contains(body, "<script>") {
		t.Errorf("page %s, want the escaped message and the code", body)
	}

	api := httptest.NewRecorder()
	writeSSOError(api, httptest.NewRequest(http.MethodGet, "/saml/idp/x/sso", nil), err)
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if jsonErr := json.Unmarshal(api.Body.Bytes(), &envelope); jsonErr != nil || api.Code != http.StatusForbidden || envelope.Error.Code != CodeNameIDUnavailable {
		t.Errorf("JSON answer %d %s, want 403 %s", api.Code, api.Body.String(), CodeNameIDUnavailable)
	}
}
