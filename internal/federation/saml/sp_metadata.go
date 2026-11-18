package saml

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// publicBase returns the origin SAML entity IDs and endpoint URLs are built on.
func (h *Handler) publicBase(r *http.Request) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL)
}

func spEntityID(base string, id uuid.UUID) string { return base + "/saml/metadata/" + id.String() }

func acsURL(base string, id uuid.UUID) string { return base + "/saml/acs/" + id.String() }

// SPAddresses are what an IdP is told about a connection's service provider:
// its entity ID, where it receives assertions, and where its metadata is.
type SPAddresses struct {
	EntityID    string `json:"sp_entity_id"`
	ACSURL      string `json:"acs_url"`
	MetadataURL string `json:"sp_metadata_url"`
}

// Addresses returns connection id's service provider addresses on base, the
// API's public origin. The entity ID is the metadata's own URL.
func Addresses(base string, id uuid.UUID) SPAddresses {
	return SPAddresses{EntityID: spEntityID(base, id), ACSURL: acsURL(base, id), MetadataURL: spEntityID(base, id)}
}

// buildSP returns the gosaml2 service provider for conn, with its entity ID,
// audience and ACS URL built on base, trusting signatures by certs.
func (s *Service) buildSP(base string, conn *Connection, certs []*x509.Certificate) *saml2.SAMLServiceProvider {
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      conn.IdpSSOURL,
		IdentityProviderIssuer:      conn.IdpEntityID,
		ServiceProviderIssuer:       spEntityID(base, conn.ID),
		AssertionConsumerServiceURL: acsURL(base, conn.ID),
		AudienceURI:                 spEntityID(base, conn.ID),
		SignAuthnRequests:           false,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: certs},
	}
}

func (h *Handler) metadata(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	encryption, err := h.Service.encryptionCertificate(r.Context(), conn)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	keyDescriptor := ""
	if encryption != "" {
		keyDescriptor = fmt.Sprintf(spEncryptionKeyDescriptor, encryption)
	}
	base := h.publicBase(r)
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">%s
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`, spEntityID(base, id), keyDescriptor, acsURL(base, id))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="sp-metadata.xml"`)
	_, _ = w.Write([]byte(xml)) // #nosec G705 -- XML download, not rendered as HTML
}
