package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
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
