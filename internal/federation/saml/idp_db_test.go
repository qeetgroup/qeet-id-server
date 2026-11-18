//go:build integration

package saml

// Database tests for the per-organization SAML IdP endpoints, driving the real
// handlers through MountPublic against a migrated PostgreSQL (see dbtest).

import (
	"context"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// idpOrganizationFixture is one organization with a member signed in to the hosted login
// and a registered SP.
type idpOrganizationFixture struct {
	organizationID uuid.UUID
	cookie         string
	sp             *ServiceProvider
}

func newIdPRouter(t *testing.T, sessions sessionsByCookie) (*IdP, chi.Router) {
	t.Helper()
	idp := newTestIdP(t, dbtest.Pool(t), sessions)
	r := chi.NewRouter()
	(&Handler{Service: &Service{}, IdP: idp, PublicBaseURL: testPublicBase}).MountPublic(r)
	return idp, r
}

func registerSP(t *testing.T, ctx context.Context, idp *IdP, organizationID uuid.UUID, entityID, acs string) *ServiceProvider {
	t.Helper()
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	sp, err := idp.createSP(ctx, tx, organizationID, CreateSPInput{Name: "App", EntityID: entityID, ACSURL: acs, Status: "active"})
	if err != nil {
		t.Fatalf("CreateSP: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return sp
}

func idpGet(t *testing.T, router http.Handler, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://other.example"+path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func authnRequestQuery(issuer, id string) string {
	raw := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + id + `">` +
		`<saml:Issuer>` + issuer + `</saml:Issuer></samlp:AuthnRequest>`
	return "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(fuzzDeflate(raw)))
}

var (
	formActionRe   = regexp.MustCompile(`<form method="POST" action="([^"]*)"`)
	samlResponseRe = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
	issuerRe       = regexp.MustCompile(`<saml:Issuer[^>]*>([^<]*)</saml:Issuer>`)
)

// postedTo returns the ACS URL a successful SSO response posts to and the
// response's issuer.
func postedTo(t *testing.T, rec *httptest.ResponseRecorder) (acs, issuer string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("SSO = %d %s, want 200", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	action := formActionRe.FindStringSubmatch(body)
	value := samlResponseRe.FindStringSubmatch(body)
	if action == nil || value == nil {
		t.Fatalf("SSO response has no POST form: %s", body)
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(value[1]))
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	iss := issuerRe.FindStringSubmatch(string(xml))
	if iss == nil {
		t.Fatalf("SAMLResponse has no Issuer: %s", xml)
	}
	return html.UnescapeString(action[1]), iss[1]
}
