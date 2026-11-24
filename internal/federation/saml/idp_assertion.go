package saml

import (
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
)

// buildSignedResponse constructs a SAML Response wrapping a signed Assertion
// about s. inResponseTo is empty for IdP-initiated SSO.
func (i *IdP) buildSignedResponse(idpEntity string, sp *ServiceProvider, acs string, s assertionSubject, inResponseTo string) ([]byte, error) {
	now := time.Now().UTC()
	respID := "_" + uuid.NewString()
	assertID := "_" + uuid.NewString()
	assertion := assertionElement(idpEntity, sp, acs, s, inResponseTo, now, assertID)

	// --- Response wrapping the assertion ---
	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("ID", respID)
	resp.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	resp.CreateAttr("Destination", acs)
	if inResponseTo != "" {
		resp.CreateAttr("InResponseTo", inResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(idpEntity)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", statusSuccess)
	resp.AddChild(assertion)

	// Sign the assertion in place inside the Response, so the canonical form the SP
	// checks matches what was signed, then move ds:Signature after saml:Issuer.
	ctx, err := i.signer.signingContext()
	if err != nil {
		return nil, err
	}
	signed, err := ctx.SignEnveloped(assertion)
	if err != nil {
		return nil, err
	}
	moveSignatureAfterIssuer(signed)
	resp.RemoveChild(assertion)
	// An app that asked for encrypted assertions gets the signed assertion
	// encrypted to its certificate.
	if sp.EncryptAssertions {
		cert, err := parseCertificate(sp.Certificate)
		if err != nil {
			return nil, err
		}
		if signed, err = sealAssertion(signed, cert); err != nil {
			return nil, err
		}
	}
	resp.AddChild(signed)

	doc := etree.NewDocument()
	doc.SetRoot(resp)
	return doc.WriteToBytes()
}

// assertionElement builds the assertion with ID assertID, issued at now by
// idpEntity, about s, for sp's audience at acs, unsigned: buildSignedResponse
// signs it once inside the Response.
func assertionElement(idpEntity string, sp *ServiceProvider, acs string, s assertionSubject, inResponseTo string, now time.Time, assertID string) *etree.Element {
	notBefore := now.Add(-clockSkew).Format(time.RFC3339)
	notAfter := now.Add(assertionTTL).Format(time.RFC3339)
	nidFormat := s.nameIDFormat
	if nidFormat == "" {
		nidFormat = nameIDEmail
	}

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", nsAssertion)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("ID", assertID)
	assertion.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	assertion.CreateElement("saml:Issuer").SetText(idpEntity)

	subject := assertion.CreateElement("saml:Subject")
	nid := subject.CreateElement("saml:NameID")
	nid.CreateAttr("Format", nidFormat)
	nid.SetText(s.nameID)
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", confirmationBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", notAfter)
	scd.CreateAttr("Recipient", acs)
	if inResponseTo != "" {
		scd.CreateAttr("InResponseTo", inResponseTo)
	}

	cond := assertion.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", notBefore)
	cond.CreateAttr("NotOnOrAfter", notAfter)
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(sp.EntityID)

	authn := assertion.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", now.Format(time.RFC3339))
	authn.CreateAttr("SessionIndex", assertID)
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(authnCtxPassword)

	// The schema wants an AttributeStatement to hold an attribute, so one with
	// none is left out.
	var attrStmt *etree.Element
	if len(s.attributes) > 0 {
		attrStmt = assertion.CreateElement("saml:AttributeStatement")
	}
	for _, attr := range s.attributes {
		a := attrStmt.CreateElement("saml:Attribute")
		a.CreateAttr("Name", attr.name)
		a.CreateAttr("NameFormat", attr.nameFormat)
		for _, v := range attr.values {
			a.CreateElement("saml:AttributeValue").SetText(v)
		}
	}
	return assertion
}

// moveSignatureAfterIssuer moves ds:Signature to just after saml:Issuer, where
// the schema puts it and strict SPs such as ADFS require it. It edits el.Child
// directly because goxmldsig leaves etree's child indexes stale. An enveloped
// signature doesn't cover itself, so moving it keeps it valid.
func moveSignatureAfterIssuer(el *etree.Element) {
	sigIdx, issuerIdx := -1, -1
	for i, tok := range el.Child {
		e, ok := tok.(*etree.Element)
		if !ok {
			continue
		}
		switch e.Tag {
		case "Signature":
			if sigIdx < 0 {
				sigIdx = i
			}
		case "Issuer":
			if issuerIdx < 0 {
				issuerIdx = i
			}
		}
	}
	if sigIdx < 0 || issuerIdx < 0 {
		return
	}
	target := issuerIdx + 1
	if sigIdx == target {
		return
	}
	sig := el.Child[sigIdx]
	el.Child = append(el.Child[:sigIdx], el.Child[sigIdx+1:]...)
	if target > sigIdx {
		target--
	}
	tail := append([]etree.Token{sig}, el.Child[target:]...)
	el.Child = append(el.Child[:target], tail...)
}
