package saml

import (
	"fmt"
	"html"
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// idpEntityID is the organization's IdP entity ID.
func idpEntityID(base string, organizationID uuid.UUID) string {
	return base + "/saml/idp/" + organizationID.String()
}

// idpSSOURL is the organization's IdP SingleSignOnService URL.
func idpSSOURL(base string, organizationID uuid.UUID) string {
	return idpEntityID(base, organizationID) + "/sso"
}

// idpMetadata serves the organization's IdP SAML metadata (EntityDescriptor) for SPs
// to import: the signing cert + SSO endpoints.
func (h *Handler) idpMetadata(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		httpx.WriteError(w, r, ErrIdPNotConfigured)
		return
	}
	organizationID, err := h.idpOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	base := h.publicBase(r)
	entity := idpEntityID(base, organizationID)
	sso := idpSSOURL(base, organizationID)
	doc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>%s</NameIDFormat>
    <NameIDFormat>%s</NameIDFormat>
    <NameIDFormat>%s</NameIDFormat>
    <SingleSignOnService Binding="%s" Location="%s"/>
    <SingleSignOnService Binding="%s" Location="%s"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
		html.EscapeString(entity), h.IdP.signer.certB64, nameIDEmail, nameIDPersistent, nameIDUnspecified,
		bindingRedirect, html.EscapeString(sso), bindingPOST, html.EscapeString(sso))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="qeet-idp-metadata.xml"`)
	_, _ = w.Write([]byte(doc))
}
