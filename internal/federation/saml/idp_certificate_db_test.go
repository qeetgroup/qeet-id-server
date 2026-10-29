//go:build integration

package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- decrypts rsa-oaep-mgf1p as an SP would
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// spKeys is an app's own signing and encryption key, as an SP holds it.
type spKeys struct {
	certPEM string
	signer  *idpSigner
}

func newSPKeys(t *testing.T) spKeys {
	t.Helper()
	keyPEM, certPEM, err := GenerateIdPKeyPEM("App SP")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return spKeys{certPEM: certPEM, signer: signer}
}

// ecdsaCertPEM is a certificate for an ECDSA key, which can't be encrypted to.
func ecdsaCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "EC app"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// createSP registers an app in tenant within its own transaction.
func createSP(t *testing.T, idp *IdP, tenant uuid.UUID, in CreateSPInput) (*ServiceProvider, error) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	sp, err := idp.CreateSP(ctx, tx, tenant, in)
	if err != nil {
		return nil, err
	}
	return sp, tx.Commit(ctx)
}

// updateSP changes an app within its own transaction.
func updateSP(t *testing.T, idp *IdP, sp *ServiceProvider, in UpdateSPInput) (*ServiceProvider, error) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	out, err := idp.UpdateSP(ctx, tx, sp.ID, sp.TenantID, in)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// TestAppCertificatesSayWhatTheyAreFor checks that an app's certificate is
// kept only for verifying its requests or encrypting its assertions, that
// either needs one, that encryption needs an RSA key, and that the app shows
// what the certificate says.
func TestAppCertificatesSayWhatTheyAreFor(t *testing.T) {
	s := newIdPSide(t)
	tenant := dbtest.Tenant(t)
	keys := newSPKeys(t)
	app := func(entity string) CreateSPInput {
		return CreateSPInput{Name: "App", EntityID: entity, ACSURL: "https://app.example.test/acs", Status: "active"}
	}

	in := app("https://app.example.test/unused")
	in.Certificate = keys.certPEM
	if _, err := createSP(t, s.idp, tenant, in); !errors.Is(err, errs.ErrSAMLCertificateUnused) {
		t.Errorf("a certificate for nothing: %v, want certificate_unused", err)
	}
	in = app("https://app.example.test/none")
	in.EncryptAssertions = true
	if _, err := createSP(t, s.idp, tenant, in); !errors.Is(err, errs.ErrSAMLCertificateRequired) {
		t.Errorf("encryption with no certificate: %v, want certificate_required", err)
	}
	in = app("https://app.example.test/ec")
	in.Certificate, in.EncryptAssertions = ecdsaCertPEM(t), true
	if _, err := createSP(t, s.idp, tenant, in); !errors.Is(err, errs.ErrSAMLEncryptionKeyUnsupported) {
		t.Errorf("encryption to an ECDSA key: %v, want encryption_key_unsupported", err)
	}

	in = app("https://app.example.test/ok")
	in.Certificate, in.RequireSignedRequests = keys.certPEM, true
	sp, err := createSP(t, s.idp, tenant, in)
	if err != nil {
		t.Fatal(err)
	}
	d := sp.CertificateDetails
	if d == nil || d.Subject != "CN=App SP" || len(d.FingerprintSHA256) != 95 || !d.NotAfter.After(time.Now()) {
		t.Errorf("certificate details %+v, want its subject, SHA-256 fingerprint and validity", d)
	}
	off := false
	if _, err := updateSP(t, s.idp, sp, UpdateSPInput{RequireSignedRequests: &off}); !errors.Is(err, errs.ErrSAMLCertificateUnused) {
		t.Errorf("turning off the certificate's only use: %v, want certificate_unused", err)
	}
	none := ""
	if _, err := updateSP(t, s.idp, sp, UpdateSPInput{Certificate: &none}); !errors.Is(err, errs.ErrSAMLCertificateRequired) {
		t.Errorf("removing the certificate signed requests need: %v, want certificate_required", err)
	}
	cleared, err := updateSP(t, s.idp, sp, UpdateSPInput{Certificate: &none, RequireSignedRequests: &off})
	if err != nil || cleared.Certificate != "" || cleared.RequireSignedRequests || cleared.CertificateDetails != nil {
		t.Errorf("removing the certificate with its use: %+v, %v", cleared, err)
	}
}

// signedRedirectQuery is a Redirect-binding SAMLRequest from issuer, signed
// with key over its query as the binding defines.
func signedRedirectQuery(t *testing.T, key *rsa.PrivateKey, issuer, id, relay string) string {
	t.Helper()
	q := authnRequestTo(issuer, id, "")
	q += "&RelayState=" + url.QueryEscape(relay) + "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	sum := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// signedPostRequest is a POST-binding AuthnRequest from issuer with an
// enveloped signature by keys.
func signedPostRequest(t *testing.T, keys spKeys, issuer, id string) string {
	t.Helper()
	doc := etree.NewDocument()
	raw := `<samlp:AuthnRequest xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `" ID="` + id +
		`" Version="2.0"><saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatal(err)
	}
	sctx, err := keys.signer.signingContext()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// idpPost posts a SAMLRequest to the SSO endpoint with a hosted-login session.
func idpPost(t *testing.T, router http.Handler, path, samlRequest, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"SAMLRequest": {samlRequest}}
	req := httptest.NewRequest(http.MethodPost, "https://other.example"+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestSignedRequestsAreRequiredWhenAsked checks that an app set to sign its
// requests is signed in only by a request its certificate signed, over either
// binding, and that IdP-started sign-in still works.
func TestSignedRequestsAreRequiredWhenAsked(t *testing.T) {
	s := newIdPSide(t)
	tenant := dbtest.Tenant(t)
	member := dbtest.User(t, tenant, tenant)
	cookie := s.signIn(member.ID)
	keys, impostor := newSPKeys(t), newSPKeys(t)
	sp, err := createSP(t, s.idp, tenant, CreateSPInput{Name: "App", EntityID: "https://signed.example.test/sp",
		ACSURL: "https://signed.example.test/acs", Status: "active", Certificate: keys.certPEM, RequireSignedRequests: true})
	if err != nil {
		t.Fatal(err)
	}
	sso := "/saml/idp/" + tenant.String() + "/sso"
	refused := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeSAMLRequestSignatureInvalid) {
			t.Errorf("%s: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), errs.CodeSAMLRequestSignatureInvalid)
		}
	}

	refused("an unsigned request", idpGet(t, s.router, sso+"?"+authnRequestTo(sp.EntityID, "_r1", ""), cookie))
	refused("a request signed with another key", idpGet(t, s.router, sso+"?"+signedRedirectQuery(t, impostor.signer.key, sp.EntityID, "_r2", "back"), cookie))
	tampered := strings.Replace(signedRedirectQuery(t, keys.signer.key, sp.EntityID, "_r3", "back"), "RelayState=back", "RelayState=elsewhere", 1)
	refused("a signed request whose relay state was changed", idpGet(t, s.router, sso+"?"+tampered, cookie))
	if acs, _ := postedTo(t, idpGet(t, s.router, sso+"?"+signedRedirectQuery(t, keys.signer.key, sp.EntityID, "_r4", "back"), cookie)); acs != sp.ACSURL {
		t.Errorf("a signed Redirect-binding request posted to %q", acs)
	}
	if acs, _ := postedTo(t, idpPost(t, s.router, sso, signedPostRequest(t, keys, sp.EntityID, "_r5"), cookie)); acs != sp.ACSURL {
		t.Errorf("a signed POST-binding request posted to %q", acs)
	}
	refused("a POST-binding request signed with another key", idpPost(t, s.router, sso, signedPostRequest(t, impostor, sp.EntityID, "_r6"), cookie))
	if acs, _ := postedTo(t, idpGet(t, s.router, sso+"?sp="+url.QueryEscape(sp.EntityID), cookie)); acs != sp.ACSURL {
		t.Errorf("IdP-started sign-in posted to %q", acs)
	}
}

// TestAssertionsAreEncryptedWhenAsked checks that an app set to receive
// encrypted assertions gets the signed assertion only encrypted to its key,
// which it decrypts and verifies with the IdP's published certificate, which
// is also served on its own.
func TestAssertionsAreEncryptedWhenAsked(t *testing.T) {
	s := newIdPSide(t)
	tenant := dbtest.Tenant(t)
	member := dbtest.User(t, tenant, tenant)
	cookie := s.signIn(member.ID)
	keys := newSPKeys(t)
	sp, err := createSP(t, s.idp, tenant, CreateSPInput{Name: "App", EntityID: "https://sealed.example.test/sp",
		ACSURL: "https://sealed.example.test/acs", Status: "active", Certificate: keys.certPEM, EncryptAssertions: true})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/saml/idp/" + tenant.String()

	rec := idpGet(t, s.router, prefix+"/certificate", "")
	block, _ := pem.Decode(rec.Body.Bytes())
	if rec.Code != http.StatusOK || block == nil || block.Type != "CERTIFICATE" || rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("IdP certificate download: %d %q", rec.Code, rec.Body.String())
	}
	idpCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if meta := idpGet(t, s.router, prefix+"/metadata", ""); !strings.Contains(meta.Body.String(), base64.StdEncoding.EncodeToString(block.Bytes)) {
		t.Error("the downloaded certificate isn't the one in the metadata")
	}

	rec = idpGet(t, s.router, prefix+"/sso?"+authnRequestTo(sp.EntityID, "_e1", ""), cookie)
	value := samlResponseRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || value == nil {
		t.Fatalf("SSO: %d %s", rec.Code, rec.Body.String())
	}
	respXML, err := base64.StdEncoding.DecodeString(html.UnescapeString(value[1]))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(respXML), "<saml:Assertion") || strings.Contains(string(respXML), member.Email) {
		t.Fatal("the response carries the assertion in the clear")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(respXML); err != nil {
		t.Fatal(err)
	}
	keyValue := doc.FindElement("//EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey/CipherData/CipherValue")
	dataValue := doc.FindElement("//EncryptedAssertion/EncryptedData/CipherData/CipherValue")
	if keyValue == nil || dataValue == nil {
		t.Fatalf("encrypted assertion lacks the key or the data: %s", respXML)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(keyValue.Text())
	sealed, _ := base64.StdEncoding.DecodeString(dataValue.Text())
	key, err := rsa.DecryptOAEP(sha1.New(), nil, keys.signer.key, wrapped, nil) // #nosec G401 -- rsa-oaep-mgf1p
	if err != nil {
		t.Fatalf("decrypt the content key: %v", err)
	}
	blockCipher, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blockCipher)
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("decrypt the assertion: %v", err)
	}
	assertion := etree.NewDocument()
	if err := assertion.ReadFromBytes(plain); err != nil {
		t.Fatal(err)
	}
	vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{idpCert}})
	vctx.IdAttribute = "ID"
	verified, err := vctx.Validate(assertion.Root())
	if err != nil {
		t.Fatalf("the decrypted assertion's signature: %v", err)
	}
	if nid := verified.FindElement(".//NameID"); nid == nil || nid.Text() != member.Email {
		t.Errorf("decrypted assertion names %v, want %s", nid, member.Email)
	}
}
