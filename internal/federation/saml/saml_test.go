package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	samltypes "github.com/russellhaering/gosaml2/types"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	s := &Service{}
	sp, err := s.buildSP("https://auth.acme.com", conn)
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
	sp, err := configured.Service.buildSP(configured.publicBase(other), conn)
	if err != nil {
		t.Fatalf("buildSP: %v", err)
	}
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

func TestValidIdPSSOURL(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{"https://idp.example.com/sso", true},
		{"https://idp.example.com:8443/app/sso?idpid=abc", true},
		{"HTTPS://IDP.EXAMPLE.COM/sso", true},
		{"http://idp.example.com/sso", false},
		{"http://localhost:8080/sso", false},
		{"https://user:pass@idp.example.com/sso", false},
		{"https://@idp.example.com/sso", false},
		{"https:///sso", false},
		{"https://:443/sso", false},
		{"https:idp.example.com/sso", false},
		{"//idp.example.com/sso", false},
		{"/sso", false},
		{"javascript:alert(1)", false},
		{"https://idp.example.com/\tsso", false},
		{"", false},
	} {
		if got := validIdPSSOURL(c.raw); got != c.want {
			t.Errorf("validIdPSSOURL(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestConnectionWritesRejectInvalidSSOURL checks that creating or updating a
// connection refuses an SSO URL that isn't an absolute https URL.
func TestConnectionWritesRejectInvalidSSOURL(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	tenant := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	user := uuid.New()
	principal := &httpx.Principal{UserID: &user, TenantID: &tenant, ActorType: "user", Subject: user.String()}
	router := chi.NewRouter()
	(&Handler{Service: &Service{}}).Mount(router)

	send := func(method, path string, body map[string]any) *httptest.ResponseRecorder {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(httpx.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	base := "/tenants/" + tenant.String() + "/saml"
	for _, sso := range []string{"http://idp.example.com/sso", "https://user@idp.example.com/sso", "idp.example.com/sso"} {
		create := send(http.MethodPost, base, map[string]any{
			"name": "IdP", "idp_entity_id": "https://idp.example.com", "idp_sso_url": sso, "idp_certificate": pemStr,
		})
		if create.Code != http.StatusUnprocessableEntity || !strings.Contains(create.Body.String(), errs.CodeSAMLSSOURLInvalid) {
			t.Errorf("create with %q = %d %s, want 422 %s", sso, create.Code, create.Body.String(), errs.CodeSAMLSSOURLInvalid)
		}
		update := send(http.MethodPatch, base+"/"+uuid.NewString(), map[string]any{"idp_sso_url": sso})
		if update.Code != http.StatusUnprocessableEntity || !strings.Contains(update.Body.String(), errs.CodeSAMLSSOURLInvalid) {
			t.Errorf("update with %q = %d %s, want 422 %s", sso, update.Code, update.Body.String(), errs.CodeSAMLSSOURLInvalid)
		}
	}
}

// TestServiceRefusesInvalidConnections checks that Service.Create and Update
// apply the SSO URL and certificate checks themselves, for callers other than
// this package's handlers, such as the admin portal.
func TestServiceRefusesInvalidConnections(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	svc, tenant := &Service{}, uuid.New()
	ctx := context.Background()
	for _, c := range []struct {
		name string
		in   CreateInput
		want error
	}{
		{"script URL", CreateInput{IdpSSOURL: "javascript:alert(1)", IdpCertificate: pemStr}, errs.ErrSAMLSSOURLInvalid},
		{"plain http", CreateInput{IdpSSOURL: "http://idp.example.com/sso", IdpCertificate: pemStr}, errs.ErrSAMLSSOURLInvalid},
		{"bad certificate", CreateInput{IdpSSOURL: "https://idp.example.com/sso", IdpCertificate: "not a cert"}, errs.ErrSAMLCertificateInvalid},
	} {
		if _, err := svc.Create(ctx, nil, tenant, c.in); !errors.Is(err, c.want) {
			t.Errorf("create with %s: %v, want %v", c.name, err, c.want)
		}
	}
	bad, cert := "http://idp.example.com/sso", "not a cert"
	if _, err := svc.Update(ctx, nil, uuid.New(), tenant, UpdateInput{IdpSSOURL: &bad}); !errors.Is(err, errs.ErrSAMLSSOURLInvalid) {
		t.Errorf("update with plain http: %v", err)
	}
	if _, err := svc.Update(ctx, nil, uuid.New(), tenant, UpdateInput{IdpCertificate: &cert}); !errors.Is(err, errs.ErrSAMLCertificateInvalid) {
		t.Errorf("update with a bad certificate: %v", err)
	}
}

func TestTrustedCorrelationIgnoresUnsignedResponseEnvelope(t *testing.T) {
	response := &samltypes.Response{
		InResponseTo: "_forged-envelope-request",
		Assertions: []samltypes.Assertion{{
			ID:                 "_signed-assertion",
			SignatureValidated: true,
			Subject: &samltypes.Subject{SubjectConfirmation: &samltypes.SubjectConfirmation{
				SubjectConfirmationData: &samltypes.SubjectConfirmationData{InResponseTo: "_trusted-request"},
			}},
		}},
	}

	requestID, assertionIDs, err := trustedCorrelation(response)
	if err != nil {
		t.Fatalf("trustedCorrelation: %v", err)
	}
	if requestID != "_trusted-request" {
		t.Fatalf("request ID = %q, want signed assertion value", requestID)
	}
	if len(assertionIDs) != 1 || assertionIDs[0] != "_signed-assertion" {
		t.Fatalf("assertion IDs = %v, want signed assertion ID", assertionIDs)
	}
}
