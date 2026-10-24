//go:build integration

package saml

// Database tests for the organisation's SAML IdP issuing assertions, with the
// hosted-login session resolved by the real authentication service.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// metadataCertRe finds the signing certificate in IdP metadata.
var metadataCertRe = regexp.MustCompile(`<X509Certificate>([^<]+)</X509Certificate>`)

// idpSide is the organisation-facing IdP, its public routes and a way to open
// a hosted-login session.
type idpSide struct {
	idp    *IdP
	router chi.Router
	signIn func(userID uuid.UUID) string
}

// newIdPSide returns the IdP, resolving hosted-login sessions with the real
// authentication service.
func newIdPSide(t *testing.T) *idpSide {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(pool, keyPEM, certPEM, "https://login.id.qeet.in", authSvc)
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	(&Handler{Service: &Service{}, IdP: idp, PublicBaseURL: testPublicBase}).MountPublic(router)
	signIn := func(userID uuid.UUID) string {
		raw, err := authSvc.CreateLoginSession(dbtest.Context(t), userID, "203.0.113.7", "test")
		if err != nil {
			t.Fatalf("hosted-login session: %v", err)
		}
		return raw
	}
	return &idpSide{idp: idp, router: router, signIn: signIn}
}

// authnRequestTo is a Redirect-binding SAMLRequest query from issuer, asking
// for the assertion at acs ("" leaves the registered one).
func authnRequestTo(issuer, id, acs string) string {
	raw := `<samlp:AuthnRequest xmlns:samlp="` + nsProtocol + `" xmlns:saml="` + nsAssertion + `" ID="` + id + `"`
	if acs != "" {
		raw += ` AssertionConsumerServiceURL="` + acs + `"`
	}
	raw += `><saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
	return "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(fuzzDeflate(raw)))
}

// setSPStatus changes a service provider's status.
func setSPStatus(t *testing.T, ctx context.Context, idp *IdP, sp *ServiceProvider, status string) {
	t.Helper()
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := idp.UpdateSP(ctx, tx, sp.ID, sp.TenantID, UpdateSPInput{Status: &status}); err != nil {
		t.Fatalf("set the SP %s: %v", status, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestIdPIssuesAssertionsAsRegistered checks that the organisation's IdP
// issues a recorded assertion, which a standard SP verifies with the metadata's
// certificate, only to an enabled, registered SP at its ACS URL for a signed-in
// person of the organisation; anyone else is refused or sent to sign in.
func TestIdPIssuesAssertionsAsRegistered(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	member := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, other, other)
	cookie := s.signIn(member.ID)
	sp := registerSP(t, ctx, s.idp, tenant, "https://sp.example.test/metadata", "https://sp.example.test/acs")
	prefix := "/saml/idp/" + tenant.String()
	issuer := testPublicBase + prefix

	meta := idpGet(t, s.router, prefix+"/metadata", "")
	published := metadataCertRe.FindStringSubmatch(meta.Body.String())
	if meta.Code != http.StatusOK || published == nil {
		t.Fatalf("metadata: %d %s; want the signing certificate", meta.Code, meta.Body.String())
	}
	cert, err := parseCertificate(published[1])
	if err != nil {
		t.Fatalf("published certificate: %v", err)
	}

	rec := idpGet(t, s.router, prefix+"/sso?"+authnRequestTo(sp.EntityID, "_req-1", sp.ACSURL)+"&RelayState=state-1", cookie)
	if acs, got := postedTo(t, rec); acs != sp.ACSURL || got != issuer {
		t.Errorf("SSO posted to %q as %q, want %q as %q", acs, got, sp.ACSURL, issuer)
	}
	if !strings.Contains(rec.Body.String(), `name="RelayState" value="state-1"`) {
		t.Errorf("SSO lost the RelayState: %s", rec.Body.String())
	}
	verifier := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      issuer,
		ServiceProviderIssuer:       sp.EntityID,
		AssertionConsumerServiceURL: sp.ACSURL,
		AudienceURI:                 sp.EntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
	}
	info, err := verifier.RetrieveAssertionInfo(html.UnescapeString(samlResponseRe.FindStringSubmatch(rec.Body.String())[1]))
	if err != nil {
		t.Fatalf("a standard SP refused the assertion: %v", err)
	}
	if info.WarningInfo.InvalidTime || info.WarningInfo.NotInAudience || info.NameID != member.Email ||
		info.Assertions[0].Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != "_req-1" {
		t.Errorf("assertion for %q, warnings %+v; want the member, answering _req-1, valid now for the SP", info.NameID, info.WarningInfo)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'saml.idp_assertion_issued' AND resource_id = $2 AND actor_user_id = $3`, tenant, sp.ID, member.ID); n != 1 {
		t.Errorf("%d issued assertions recorded, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_service_providers WHERE id = $1 AND last_login_at IS NOT NULL`, sp.ID); n != 1 {
		t.Error("the SP's last sign-in was not recorded")
	}

	for _, c := range []struct {
		name, query, cookie, want string
	}{
		{"an attacker's ACS URL", authnRequestTo(sp.EntityID, "_req-2", "https://evil.example.test/acs"), cookie, errs.CodeSAMLACSMismatch},
		{"an unregistered SP", authnRequestTo("https://unknown.example.test", "_req-3", ""), cookie, errs.CodeNotFound},
		{"an unreadable request", "SAMLRequest=" + url.QueryEscape("not base64!"), cookie, errs.CodeSAMLAuthnRequestInvalid},
		{"neither a request nor an SP", "RelayState=state-1", cookie, errs.CodeSAMLRequestParamMissing},
		{"another organisation's person", "sp=" + sp.ID.String(), s.signIn(outsider.ID), errs.CodeSAMLUserTenantMismatch},
	} {
		rec := idpGet(t, s.router, prefix+"/sso?"+c.query, c.cookie)
		if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), c.want) || strings.Contains(rec.Body.String(), "SAMLResponse") {
			t.Errorf("%s: %d %s, want %s", c.name, rec.Code, rec.Body.String(), c.want)
		}
	}

	for _, c := range []string{"", "not-a-session"} {
		rec := idpGet(t, s.router, prefix+"/sso?sp="+sp.ID.String(), c)
		login, err := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || err != nil || !strings.HasPrefix(login.String(), "https://login.id.qeet.in/login?") ||
			login.Query().Get("return_to") != issuer+"/sso?sp="+sp.ID.String() {
			t.Errorf("SSO with session %q: %d %s; want the hosted login, returning here", c, rec.Code, rec.Header().Get("Location"))
		}
	}

	setSPStatus(t, ctx, s.idp, sp, "disabled")
	if rec := idpGet(t, s.router, prefix+"/sso?sp="+sp.ID.String(), cookie); !strings.Contains(rec.Body.String(), errs.CodeSAMLServiceProviderDisabled) {
		t.Errorf("SSO to a disabled SP by ID: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLServiceProviderDisabled)
	}
	if rec := idpGet(t, s.router, prefix+"/sso?"+authnRequestTo(sp.EntityID, "_req-4", ""), cookie); rec.Code != http.StatusNotFound {
		t.Errorf("a request from a disabled SP: %d %s, want 404", rec.Code, rec.Body.String())
	}

	bare := chi.NewRouter()
	(&Handler{Service: &Service{}}).MountPublic(bare)
	for _, path := range []string{prefix + "/metadata", prefix + "/sso?sp=" + sp.ID.String()} {
		if rec := idpGet(t, bare, path, cookie); !strings.Contains(rec.Body.String(), errs.CodeSAMLIdPNotConfigured) {
			t.Errorf("%s without an IdP: %d %s, want %s", path, rec.Code, rec.Body.String(), errs.CodeSAMLIdPNotConfigured)
		}
	}
}

// TestIdPRefusesASuspendedAccount checks that once a person is suspended the
// organisation's IdP issues no assertion for them, though their hosted-login
// session is still open.
func TestIdPRefusesASuspendedAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	tenant := dbtest.Tenant(t)
	member := dbtest.User(t, tenant, tenant)
	cookie := s.signIn(member.ID)
	sp := registerSP(t, ctx, s.idp, tenant, "https://sp.example.test/metadata", "https://sp.example.test/acs")
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	rec := idpGet(t, s.router, "/saml/idp/"+tenant.String()+"/sso?sp="+sp.ID.String(), cookie)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Errorf("SSO for a suspended account: %d, want refused", rec.Code)
	}
}
