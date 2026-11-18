package saml

import (
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestBuildSP_URLsAndIssuer(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	conn := &Connection{
		ID:             id,
		IdpEntityID:    "https://idp.example.com/entity",
		IdpSSOURL:      "https://idp.example.com/sso",
		IdpCertificate: pemStr,
	}
	cert, err := parseCertificate(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{}
	sp := s.buildSP("https://auth.acme.com", conn, []*x509.Certificate{cert})
	wantACS := "https://auth.acme.com/saml/acs/" + id.String()
	wantEntity := "https://auth.acme.com/saml/metadata/" + id.String()
	if sp.AssertionConsumerServiceURL != wantACS {
		t.Errorf("ACS = %q, want %q", sp.AssertionConsumerServiceURL, wantACS)
	}
	if sp.ServiceProviderIssuer != wantEntity || sp.AudienceURI != wantEntity {
		t.Errorf("SP issuer/audience = %q/%q, want %q", sp.ServiceProviderIssuer, sp.AudienceURI, wantEntity)
	}
	if sp.IdentityProviderSSOURL != conn.IdpSSOURL || sp.IdentityProviderIssuer != conn.IdpEntityID {
		t.Errorf("IdP fields not wired through")
	}
	if sp.SignAuthnRequests {
		t.Error("SignAuthnRequests should be false (no SP key configured)")
	}
	if roots, err := sp.IDPCertificateStore.Certificates(); err != nil || len(roots) != 1 || !roots[0].Equal(cert) {
		t.Errorf("IdP certificate store holds %v, %v; want the connection's certificate", roots, err)
	}
}

// TestPublicBaseUsesConfiguredOrigin checks that SAML URLs are built on
// PublicBaseURL whatever the request's Host, and that for a request to the
// configured host they equal the Host-derived ones.
func TestPublicBaseUsesConfiguredOrigin(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	conn := &Connection{ID: id, IdpSSOURL: "https://idp.example.com/sso", IdpCertificate: pemStr}
	configured := &Handler{Service: &Service{}, PublicBaseURL: "https://api.id.qeet.in/"}

	other := httptest.NewRequest("GET", "https://other.example/saml/login/"+id.String(), nil)
	other.Host = "other.example"
	sp := configured.Service.buildSP(configured.publicBase(other), conn, nil)
	wantEntity := "https://api.id.qeet.in/saml/metadata/" + id.String()
	if sp.AudienceURI != wantEntity || sp.ServiceProviderIssuer != wantEntity {
		t.Errorf("audience/issuer = %q/%q, want %q", sp.AudienceURI, sp.ServiceProviderIssuer, wantEntity)
	}
	if want := "https://api.id.qeet.in/saml/acs/" + id.String(); sp.AssertionConsumerServiceURL != want {
		t.Errorf("ACS = %q, want %q", sp.AssertionConsumerServiceURL, want)
	}

	same := httptest.NewRequest("GET", "https://api.id.qeet.in/saml/metadata/"+id.String(), nil)
	same.Host = "api.id.qeet.in"
	if got, want := configured.publicBase(same), (&Handler{}).publicBase(same); got != want {
		t.Errorf("configured base = %q, Host-derived base = %q; want them equal for the configured host", got, want)
	}
}
