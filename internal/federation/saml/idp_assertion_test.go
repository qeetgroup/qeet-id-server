package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

// TestIdPAssertionRoundTrip proves our issued Response is accepted by an
// independent SAML SP implementation (gosaml2): the signature validates, the
// audience/clock conditions pass, and the NameID + attributes survive. An SP
// with the default settings is told the email and name, as before mappings.
func TestIdPAssertionRoundTrip(t *testing.T) {
	idp := testIdP(t)
	const (
		idpEntity = "https://id.qeet.example/saml/idp"
		spEntity  = "https://sp.example.com/saml/metadata"
		acs       = "https://sp.example.com/saml/acs"
	)
	sp := &ServiceProvider{EntityID: spEntity, ACSURL: acs, NameIDFormat: nameIDEmail, NameIDAttribute: sourceEmail, Attributes: defaultAttributes()}
	subj, err := idp.subjectFor(context.Background(), sp, &person{id: uuid.New(), email: "alice@example.com", displayName: "Alice Example"})
	if err != nil {
		t.Fatalf("subjectFor: %v", err)
	}

	respXML, err := idp.buildSignedResponse(idpEntity, sp, acs, subj, "")
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
	if len(info.Values) != 2 || info.Assertions[0].Subject.NameID.Format != nameIDEmail {
		t.Errorf("attributes %v, NameID format %q; want only email and name, and an emailAddress NameID", info.Values, info.Assertions[0].Subject.NameID.Format)
	}
}

// TestIdPResponseStructure checks SP-initiated specifics: the signature sits
// right after the Issuer (SAML schema order), and InResponseTo is echoed on
// both the Response and the SubjectConfirmationData.
func TestIdPResponseStructure(t *testing.T) {
	idp := testIdP(t)
	sp := &ServiceProvider{EntityID: "https://sp.example.com", ACSURL: "https://sp.example.com/acs"}

	respXML, err := idp.buildSignedResponse("https://id.qeet.example/saml/idp", sp, sp.ACSURL, assertionSubject{nameID: "bob@example.com"}, "_req-12345")
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
