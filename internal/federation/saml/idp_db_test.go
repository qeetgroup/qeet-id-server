//go:build integration

package saml

// Database tests for the per-organisation SAML IdP endpoints, driving the real
// handlers through MountPublic against a migrated PostgreSQL (see dbtest).

import (
	"context"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

const testPublicBase = "https://api.id.qeet.in"

// sessionsByCookie resolves a hosted-login cookie value to its user.
type sessionsByCookie map[string]uuid.UUID

func (s sessionsByCookie) ResolveLoginSession(_ context.Context, raw string) (uuid.UUID, error) {
	if id, ok := s[raw]; ok {
		return id, nil
	}
	return uuid.Nil, errors.New("no session")
}

// idpTenantFixture is one tenant with a member signed in to the hosted login
// and a registered SP.
type idpTenantFixture struct {
	tenantID uuid.UUID
	cookie   string
	sp       *ServiceProvider
}

func newIdPRouter(t *testing.T, sessions sessionsByCookie) (*IdP, chi.Router) {
	t.Helper()
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatalf("GenerateIdPKeyPEM: %v", err)
	}
	idp, err := NewIdP(dbtest.Pool(t), keyPEM, certPEM, "https://login.id.qeet.in", sessions)
	if err != nil {
		t.Fatalf("NewIdP: %v", err)
	}
	r := chi.NewRouter()
	(&Handler{Service: &Service{}, IdP: idp, PublicBaseURL: testPublicBase}).MountPublic(r)
	return idp, r
}

func registerSP(t *testing.T, ctx context.Context, idp *IdP, tenantID uuid.UUID, entityID, acs string) *ServiceProvider {
	t.Helper()
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	sp, err := idp.CreateSP(ctx, tx, tenantID, CreateSPInput{Name: "App", EntityID: entityID, ACSURL: acs, Status: "active"})
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

// TestIdPSameEntityIDInTwoTenants checks that two tenants registering the same
// SP entity ID each get their own SP configuration and IdP identity.
func TestIdPSameEntityIDInTwoTenants(t *testing.T) {
	ctx := dbtest.Context(t)
	const entityID = "https://sp.example.com/saml/metadata"
	sessions := sessionsByCookie{}
	idp, router := newIdPRouter(t, sessions)

	var fixtures []idpTenantFixture
	for i := range 2 {
		tenantID := dbtest.Tenant(t)
		member := dbtest.User(t, tenantID)
		cookie := "session-" + uuid.NewString()
		sessions[cookie] = member.ID
		acs := "https://sp.example.com/acs/" + string(rune('a'+i))
		fixtures = append(fixtures, idpTenantFixture{tenantID, cookie, registerSP(t, ctx, idp, tenantID, entityID, acs)})
	}

	for _, f := range fixtures {
		prefix := "/saml/idp/" + f.tenantID.String()
		wantIssuer := testPublicBase + prefix

		acs, issuer := postedTo(t, idpGet(t, router, prefix+"/sso?"+authnRequestQuery(entityID, "_req-1"), f.cookie))
		if acs != f.sp.ACSURL || issuer != wantIssuer {
			t.Errorf("SP-initiated SSO for %s posted to %q as %q, want %q as %q", f.tenantID, acs, issuer, f.sp.ACSURL, wantIssuer)
		}
		for _, ref := range []string{url.QueryEscape(entityID), f.sp.ID.String()} {
			acs, issuer = postedTo(t, idpGet(t, router, prefix+"/sso?sp="+ref, f.cookie))
			if acs != f.sp.ACSURL || issuer != wantIssuer {
				t.Errorf("IdP-initiated SSO (sp=%s) for %s posted to %q as %q, want %q as %q", ref, f.tenantID, acs, issuer, f.sp.ACSURL, wantIssuer)
			}
		}

		meta := idpGet(t, router, prefix+"/metadata", "")
		if meta.Code != http.StatusOK ||
			!strings.Contains(meta.Body.String(), `entityID="`+wantIssuer+`"`) ||
			!strings.Contains(meta.Body.String(), `Location="`+wantIssuer+`/sso"`) {
			t.Errorf("metadata for %s = %d %s, want entity %s", f.tenantID, meta.Code, meta.Body.String(), wantIssuer)
		}
	}

	// One tenant's SSO endpoint never resolves another tenant's SP by its ID.
	a, b := fixtures[0], fixtures[1]
	if rec := idpGet(t, router, "/saml/idp/"+a.tenantID.String()+"/sso?sp="+b.sp.ID.String(), a.cookie); rec.Code != http.StatusNotFound {
		t.Errorf("tenant A SSO with tenant B's SP ID = %d %s, want 404", rec.Code, rec.Body.String())
	}
}

// TestIdPUnknownOrInactiveTenant checks that an unknown, malformed or
// suspended tenant gets the same answer as an unknown SP.
func TestIdPUnknownOrInactiveTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	_, router := newIdPRouter(t, sessionsByCookie{})
	active := dbtest.Tenant(t)
	suspended := dbtest.Tenant(t)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.tenants SET status = 'suspended' WHERE id = $1`, suspended); err != nil {
		t.Fatal(err)
	}

	unknownSP := idpGet(t, router, "/saml/idp/"+active.String()+"/sso?sp="+url.QueryEscape("https://unknown.example"), "")
	if unknownSP.Code != http.StatusNotFound {
		t.Fatalf("unknown SP = %d %s, want 404", unknownSP.Code, unknownSP.Body.String())
	}
	for _, tenant := range []string{suspended.String(), uuid.NewString(), "not-a-uuid"} {
		for _, path := range []string{"/metadata", "/sso?sp=" + url.QueryEscape("https://unknown.example")} {
			rec := idpGet(t, router, "/saml/idp/"+tenant+path, "")
			if rec.Code != unknownSP.Code || rec.Body.String() != unknownSP.Body.String() {
				t.Errorf("tenant %s %s = %d %s, want the unknown-SP answer %d %s",
					tenant, path, rec.Code, rec.Body.String(), unknownSP.Code, unknownSP.Body.String())
			}
		}
	}
}

// TestIdPPostBindingResumesAfterSignIn checks that an HTTP-POST binding
// AuthnRequest arriving without a hosted-login session is answered, once the
// person has signed in, at the URL the login returns to.
func TestIdPPostBindingResumesAfterSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	const entityID = "https://sp.example.com/saml/metadata"
	sessions := sessionsByCookie{}
	idp, router := newIdPRouter(t, sessions)
	tenantID := dbtest.Tenant(t)
	member := dbtest.User(t, tenantID)
	cookie := "session-" + uuid.NewString()
	sessions[cookie] = member.ID
	sp := registerSP(t, ctx, idp, tenantID, entityID, "https://sp.example.com/acs")

	request := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_post-1" AssertionConsumerServiceURL="` + sp.ACSURL + `">` +
		`<saml:Issuer>` + entityID + `</saml:Issuer></samlp:AuthnRequest>`
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(request))}, "RelayState": {"state-1"}}
	prefix := "/saml/idp/" + tenantID.String() + "/sso"
	req := httptest.NewRequest(http.MethodPost, "https://other.example"+prefix, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST without a session = %d %s, want 302", rec.Code, rec.Body.String())
	}
	login, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	returnTo := login.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, testPublicBase+prefix+"?") {
		t.Fatalf("return_to %q, want this tenant's SSO endpoint", returnTo)
	}

	back := idpGet(t, router, strings.TrimPrefix(returnTo, testPublicBase), cookie)
	if acs, _ := postedTo(t, back); acs != sp.ACSURL {
		t.Errorf("resumed SSO posted to %q, want %q", acs, sp.ACSURL)
	}
	if !strings.Contains(back.Body.String(), `name="RelayState" value="state-1"`) {
		t.Errorf("resumed SSO lost the RelayState: %s", back.Body.String())
	}
	xml, err := base64.StdEncoding.DecodeString(html.UnescapeString(samlResponseRe.FindStringSubmatch(back.Body.String())[1]))
	if err != nil || !strings.Contains(string(xml), `InResponseTo="_post-1"`) {
		t.Errorf("resumed SSO doesn't answer the request: %s (%v)", xml, err)
	}
}

// poolGate allows SSO to the tenants it lists, reading on the pool as the plan
// service does.
type poolGate struct {
	pool    *pgxpool.Pool
	allowed map[uuid.UUID]bool
}

func (g poolGate) FeatureAllowed(ctx context.Context, tenantID uuid.UUID, _ string) (bool, error) {
	var one int
	return g.allowed[tenantID], g.pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

// TestCreateSPPlanGateWithOneConnection checks, with only one connection free,
// that registering a service provider asks the plan first: a plan with SSO
// registers it, one without is refused, and invalid input is refused as
// invalid before the plan is asked.
func TestCreateSPPlanGateWithOneConnection(t *testing.T) {
	pool := dbtest.Pool(t)
	paid, free := dbtest.Tenant(t), dbtest.Tenant(t)
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(pool, keyPEM, certPEM, "https://login.id.qeet.in", sessionsByCookie{})
	if err != nil {
		t.Fatal(err)
	}
	idp.SetPlanGate(poolGate{pool: pool, allowed: map[uuid.UUID]bool{paid: true}})
	admins := map[uuid.UUID]uuid.UUID{paid: dbtest.User(t, paid, paid).ID, free: dbtest.User(t, free, free).ID}
	create := func(tenant uuid.UUID, acs string) *httptest.ResponseRecorder {
		h := dbtest.Serve(dbtest.Principal(admins[tenant], tenant), (&Handler{Service: &Service{}, IdP: idp}).Mount)
		return dbtest.Do(t, h, http.MethodPost, "/tenants/"+tenant.String()+"/saml-providers",
			map[string]any{"name": "App", "entity_id": "https://sp.example.com", "acs_url": acs})
	}

	dbtest.LeaveOneConnection(t)
	if rec := create(paid, "https://sp.example.com/acs"); rec.Code != http.StatusCreated {
		t.Errorf("SP in a plan with SSO = %d %s, want 201", rec.Code, rec.Body.String())
	}
	if rec := create(free, "https://sp.example.com/acs"); rec.Code != http.StatusPaymentRequired {
		t.Errorf("SP in a plan without SSO = %d %s, want 402", rec.Code, rec.Body.String())
	}
	if rec := create(free, "http://sp.example.com/acs"); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeSAMLACSURLInvalid) {
		t.Errorf("invalid SP in a plan without SSO = %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLACSURLInvalid)
	}
}
