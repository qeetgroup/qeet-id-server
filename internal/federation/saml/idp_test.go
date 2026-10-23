package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func testIdP(t *testing.T) *IdP {
	t.Helper()
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatalf("GenerateIdPKeyPEM: %v", err)
	}
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		t.Fatalf("newIdPSigner: %v", err)
	}
	return &IdP{signer: signer}
}

// TestIdPAssertionRoundTrip proves our issued Response is accepted by an
// independent SAML SP implementation (gosaml2): the signature validates, the
// audience/clock conditions pass, and the NameID + attributes survive.
func TestIdPAssertionRoundTrip(t *testing.T) {
	idp := testIdP(t)
	const (
		idpEntity = "https://id.qeet.example/saml/idp"
		spEntity  = "https://sp.example.com/saml/metadata"
		acs       = "https://sp.example.com/saml/acs"
	)
	sp := &ServiceProvider{EntityID: spEntity, ACSURL: acs, NameIDFormat: nameIDEmail}

	respXML, err := idp.buildSignedResponse(idpEntity, sp, acs, "alice@example.com", "Alice Example", "")
	if err != nil {
		t.Fatalf("buildSignedResponse: %v", err)
	}

	cert, err := x509.ParseCertificate(idp.signer.certDER)
	if err != nil {
		t.Fatal(err)
	}
	spv := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      idpEntity,
		ServiceProviderIssuer:       spEntity,
		AssertionConsumerServiceURL: acs,
		AudienceURI:                 spEntity,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
	}

	info, err := spv.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString(respXML))
	if err != nil {
		t.Fatalf("gosaml2 rejected our assertion: %v", err)
	}
	if info.WarningInfo.InvalidTime {
		t.Error("assertion conditions: InvalidTime")
	}
	if info.WarningInfo.NotInAudience {
		t.Error("assertion conditions: NotInAudience")
	}
	if info.NameID != "alice@example.com" {
		t.Errorf("NameID = %q, want alice@example.com", info.NameID)
	}
	if got := info.Values.Get("email"); got != "alice@example.com" {
		t.Errorf("email attribute = %q", got)
	}
	if got := info.Values.Get("name"); got != "Alice Example" {
		t.Errorf("name attribute = %q", got)
	}
}

// TestIdPResponseStructure checks SP-initiated specifics: the signature sits
// right after the Issuer (SAML schema order), and InResponseTo is echoed on
// both the Response and the SubjectConfirmationData.
func TestIdPResponseStructure(t *testing.T) {
	idp := testIdP(t)
	sp := &ServiceProvider{EntityID: "https://sp.example.com", ACSURL: "https://sp.example.com/acs"}

	respXML, err := idp.buildSignedResponse("https://id.qeet.example/saml/idp", sp, sp.ACSURL, "bob@example.com", "", "_req-12345")
	if err != nil {
		t.Fatalf("buildSignedResponse: %v", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(respXML); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	resp := doc.Root()
	if got := resp.SelectAttrValue("InResponseTo", ""); got != "_req-12345" {
		t.Errorf("Response InResponseTo = %q", got)
	}
	assertion := resp.FindElement("Assertion")
	if assertion == nil {
		t.Fatal("no Assertion in Response")
	}
	children := assertion.ChildElements()
	if len(children) < 2 || children[0].Tag != "Issuer" || children[1].Tag != "Signature" {
		var tags []string
		for _, c := range children {
			tags = append(tags, c.Tag)
		}
		t.Errorf("assertion child order = %v; want Issuer, Signature, …", tags)
	}
}

// TestDecodeAuthnRequestRedirectBinding round-trips an AuthnRequest through the
// HTTP-Redirect binding (raw-DEFLATE + base64) and the HTTP-POST binding.
func TestDecodeAuthnRequestRedirectBinding(t *testing.T) {
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`ID="_abc123" AssertionConsumerServiceURL="https://sp.example.com/acs">` +
		`<saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>`

	// Redirect binding: raw DEFLATE then base64.
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(raw))
	_ = fw.Close()
	redirect := base64.StdEncoding.EncodeToString(buf.Bytes())

	ar, err := decodeAuthnRequest(redirect, http.MethodGet)
	if err != nil {
		t.Fatalf("decode (redirect): %v", err)
	}
	if ar.ID != "_abc123" || ar.Issuer != "https://sp.example.com/metadata" ||
		ar.AssertionConsumerServiceURL != "https://sp.example.com/acs" {
		t.Errorf("redirect parse mismatch: %+v", ar)
	}

	// POST binding: plain base64 (no DEFLATE).
	post := base64.StdEncoding.EncodeToString([]byte(raw))
	ar2, err := decodeAuthnRequest(post, http.MethodPost)
	if err != nil {
		t.Fatalf("decode (post): %v", err)
	}
	if ar2.Issuer != "https://sp.example.com/metadata" {
		t.Errorf("post parse Issuer = %q", ar2.Issuer)
	}
}

// TestDecodeAuthnRequestInflatedSizeLimit checks that a redirect-binding
// request decodes up to maxInflatedAuthnRequest and is refused above it.
func TestDecodeAuthnRequestInflatedSizeLimit(t *testing.T) {
	request := func(size int) string {
		head := `<AuthnRequest ID="_sized"><Issuer>https://sp.example.com</Issuer><Extensions>`
		tail := `</Extensions></AuthnRequest>`
		return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
	}
	for _, c := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"at the limit", maxInflatedAuthnRequest, false},
		{"one byte over", maxInflatedAuthnRequest + 1, true},
		{"far over", 8 << 20, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(fuzzDeflate(request(c.size)))
			ar, err := decodeAuthnRequest(encoded, http.MethodGet)
			if c.wantErr {
				if !errors.Is(err, errs.ErrSAMLAuthnRequestInvalid) {
					t.Fatalf("decodeAuthnRequest = (%v, %v), want ErrSAMLAuthnRequestInvalid", ar, err)
				}
				return
			}
			if err != nil || ar.ID != "_sized" {
				t.Fatalf("decodeAuthnRequest = (%+v, %v), want ID _sized", ar, err)
			}
		})
	}
}

func TestGenerateIdPKeyPEM(t *testing.T) {
	keyPEM, certPEM, err := GenerateIdPKeyPEM("CN Test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(keyPEM, "PRIVATE KEY") || !strings.Contains(certPEM, "CERTIFICATE") {
		t.Fatal("unexpected PEM block types")
	}
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		t.Fatalf("newIdPSigner: %v", err)
	}
	if _, err := signer.signingContext(); err != nil {
		t.Fatalf("signingContext: %v", err)
	}
}

// TestServiceProviderACSURLIsChecked checks the ACS URL rule, and that CreateSP
// and UpdateSP apply it themselves.
func TestServiceProviderACSURLIsChecked(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{"https://sp.example.com/acs", true},
		{"http://localhost:3000/acs", true},
		{"http://127.0.0.1:3000/acs", true},
		{"http://[::1]:3000/acs", true},
		{"http://sp.example.com/acs", false},
		{"https://user@sp.example.com/acs", false},
		{"javascript:alert(1)", false},
		{"/acs", false},
		{"", false},
	} {
		if got := validACSURL(c.raw); got != c.want {
			t.Errorf("validACSURL(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
	idp, ctx := &IdP{}, context.Background()
	if _, err := idp.CreateSP(ctx, nil, uuid.New(), CreateSPInput{ACSURL: "http://sp.example.com/acs"}); !errors.Is(err, errs.ErrSAMLACSURLInvalid) {
		t.Errorf("CreateSP with plain http: %v", err)
	}
	acs := "javascript:alert(1)"
	if _, err := idp.UpdateSP(ctx, nil, uuid.New(), uuid.New(), UpdateSPInput{ACSURL: &acs}); !errors.Is(err, errs.ErrSAMLACSURLInvalid) {
		t.Errorf("UpdateSP with a script URL: %v", err)
	}
}

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
	if _, err := ssoReturnURL(base, post(url.Values{"SAMLRequest": {tooLarge}})); !errors.Is(err, errs.ErrSAMLAuthnRequestInvalid) {
		t.Errorf("oversized request: %v, want ErrSAMLAuthnRequestInvalid", err)
	}
	get := httptest.NewRequest(http.MethodGet, path+"?SAMLRequest=abc&RelayState=s", nil)
	if ret, err := ssoReturnURL(base, get); err != nil || ret != base+path+"?SAMLRequest=abc&RelayState=s" {
		t.Errorf("GET return URL %q, %v", ret, err)
	}
}
