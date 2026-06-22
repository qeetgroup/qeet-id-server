package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// selfSignedCert returns a throwaway cert in both PEM and bare-base64-DER form.
func selfSignedCert(t *testing.T) (pemStr, b64DER string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b64DER = base64.StdEncoding.EncodeToString(der)
	return pemStr, b64DER
}

func TestParseCertificate(t *testing.T) {
	pemStr, b64DER := selfSignedCert(t)

	if _, err := parseCertificate(pemStr); err != nil {
		t.Errorf("PEM cert should parse: %v", err)
	}
	if _, err := parseCertificate(b64DER); err != nil {
		t.Errorf("bare base64 DER should parse: %v", err)
	}
	// base64 DER with copy-paste whitespace (IdP metadata is often wrapped).
	wrapped := b64DER[:40] + "\n  " + b64DER[40:]
	if _, err := parseCertificate(wrapped); err != nil {
		t.Errorf("whitespace-wrapped base64 DER should parse: %v", err)
	}
	if _, err := parseCertificate("not-a-cert"); err == nil {
		t.Error("garbage input should fail")
	}
	if _, err := parseCertificate("-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----"); err == nil {
		t.Error("malformed PEM should fail")
	}
}

func TestBuildSP_URLsAndIssuer(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	conn := &Connection{
		ID:             id,
		IdpEntityID:    "https://idp.example.com/entity",
		IdpSSOURL:      "https://idp.example.com/sso",
		IdpCertificate: pemStr,
	}
	r := httptest.NewRequest("GET", "https://auth.acme.com/saml/login/"+id.String(), nil)
	r.Host = "auth.acme.com"

	s := &Service{}
	sp, err := s.buildSP(r, conn)
	if err != nil {
		t.Fatalf("buildSP: %v", err)
	}
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
	if sp.IDPCertificateStore == nil {
		t.Error("IDP certificate store must be set")
	}
}

func TestPublicBaseScheme(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost:4000/x", nil)
	r.Host = "localhost:4000"
	if got := publicBase(r); got != "http://localhost:4000" {
		t.Errorf("localhost should be http, got %q", got)
	}
	r2 := httptest.NewRequest("GET", "https://auth.acme.com/x", nil)
	r2.Host = "auth.acme.com"
	if got := publicBase(r2); !strings.HasPrefix(got, "https://") {
		t.Errorf("non-local should be https, got %q", got)
	}
}
