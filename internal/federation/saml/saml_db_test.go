//go:build integration

package saml

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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

// poolGate allows SSO to the organizations it lists, reading on the pool as the plan
// service does.
type poolGate struct {
	pool    *pgxpool.Pool
	allowed map[uuid.UUID]bool
}

func (g poolGate) FeatureAllowed(ctx context.Context, organizationID uuid.UUID, _ string) (bool, error) {
	var one int
	return g.allowed[organizationID], g.pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

const (
	testAppBase   = "https://console.example.test"           // where the ACS hands a sign-in
	upstreamSSO   = "https://idp.example.test/sso"           // the upstream IdP's SSO endpoint
	callbackStart = testAppBase + "/sso/callback#saml_code=" // an accepted assertion's redirect, before the code
)

// upstreamIdP is an organization's external identity provider, signing what it
// issues with its own key.
type upstreamIdP struct {
	entityID string
	certPEM  string
	signer   *idpSigner
}

// newUpstreamIdP returns an identity provider with a fresh signing key.
func newUpstreamIdP(t *testing.T) *upstreamIdP {
	t.Helper()
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Upstream IdP")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newIdPSigner(keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &upstreamIdP{entityID: "https://idp.example.test/" + uuid.NewString(), certPEM: certPEM, signer: signer}
}

// answer describes a response the IdP sends. A zero field takes the value a
// correct response to the connection carries; nameID defaults to email.
type answer struct {
	inResponseTo                             string
	nameID, email                            string
	issuer, audience, recipient, destination string
	notBefore, notOnOrAfter                  time.Time
	signer                                   *idpSigner // nil: the IdP's own key
	unsigned, signResponse                   bool
	edit                                     func(response *etree.Element) // after signing
	attributes                               map[string][]string           // asserted besides email and name
}

// respond returns the base64 SAMLResponse the IdP posts to connID's ACS,
// signing the assertion unless a says otherwise.
func (p *upstreamIdP) respond(t *testing.T, connID uuid.UUID, a answer) string {
	t.Helper()
	now := time.Now().UTC()
	orDefault := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	orDefault(&a.issuer, p.entityID)
	orDefault(&a.audience, spEntityID(testPublicBase, connID))
	orDefault(&a.recipient, acsURL(testPublicBase, connID))
	orDefault(&a.destination, acsURL(testPublicBase, connID))
	orDefault(&a.nameID, a.email)
	if a.notBefore.IsZero() {
		a.notBefore = now.Add(-time.Minute)
	}
	if a.notOnOrAfter.IsZero() {
		a.notOnOrAfter = now.Add(5 * time.Minute)
	}
	if a.signer == nil {
		a.signer = p.signer
	}

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", nsAssertion)
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("ID", "_"+uuid.NewString())
	assertion.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	assertion.CreateElement("saml:Issuer").SetText(a.issuer)
	subject := assertion.CreateElement("saml:Subject")
	subject.CreateElement("saml:NameID").SetText(a.nameID)
	confirmation := subject.CreateElement("saml:SubjectConfirmation")
	confirmation.CreateAttr("Method", confirmationBearer)
	data := confirmation.CreateElement("saml:SubjectConfirmationData")
	data.CreateAttr("NotOnOrAfter", a.notOnOrAfter.Format(time.RFC3339))
	data.CreateAttr("Recipient", a.recipient)
	if a.inResponseTo != "" {
		data.CreateAttr("InResponseTo", a.inResponseTo)
	}
	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", a.notBefore.Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", a.notOnOrAfter.Format(time.RFC3339))
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(a.audience)
	attributes := assertion.CreateElement("saml:AttributeStatement")
	for _, attr := range [][2]string{{"email", a.email}, {"name", "Asha Rao"}} {
		if attr[1] == "" {
			continue
		}
		el := attributes.CreateElement("saml:Attribute")
		el.CreateAttr("Name", attr[0])
		el.CreateElement("saml:AttributeValue").SetText(attr[1])
	}
	for name, values := range a.attributes {
		el := attributes.CreateElement("saml:Attribute")
		el.CreateAttr("Name", name)
		for _, v := range values {
			el.CreateElement("saml:AttributeValue").SetText(v)
		}
	}

	signing, err := a.signer.signingContext()
	if err != nil {
		t.Fatal(err)
	}
	if !a.unsigned && !a.signResponse {
		if assertion, err = signing.SignEnveloped(assertion); err != nil {
			t.Fatalf("sign the assertion: %v", err)
		}
	}
	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", nsProtocol)
	response.CreateAttr("xmlns:saml", nsAssertion)
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("ID", "_"+uuid.NewString())
	response.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	response.CreateAttr("Destination", a.destination)
	if a.inResponseTo != "" {
		response.CreateAttr("InResponseTo", a.inResponseTo)
	}
	response.CreateElement("saml:Issuer").SetText(a.issuer)
	response.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", statusSuccess)
	response.AddChild(assertion)
	if a.signResponse {
		if response, err = signing.SignEnveloped(response); err != nil {
			t.Fatalf("sign the response: %v", err)
		}
	}
	if a.edit != nil {
		a.edit(response)
	}
	doc := etree.NewDocument()
	doc.SetRoot(response)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// spSide is the SAML service provider, its auth service and public routes,
// and the cookies of the one browser signing in.
type spSide struct {
	auth    *auth.Service
	handler *Handler
	public  chi.Router
	browser []*http.Cookie
}

// keep stores the cookies rec sets, as a browser does.
func (s *spSide) keep(rec *httptest.ResponseRecorder) {
	for _, set := range rec.Result().Cookies() {
		kept := s.browser[:0]
		for _, c := range s.browser {
			if c.Name != set.Name {
				kept = append(kept, c)
			}
		}
		s.browser = kept
		if set.MaxAge >= 0 {
			s.browser = append(s.browser, set)
		}
	}
}

// send serves req from the browser, holding its cookies.
func (s *spSide) send(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range s.browser {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.public.ServeHTTP(rec, req)
	s.keep(rec)
	return rec
}

// newSPSide returns the service provider, handing sign-ins to the console.
func newSPSide(t *testing.T) *spSide {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	h := &Handler{Service: NewService(pool, authSvc, testAppBase), PublicBaseURL: testPublicBase}
	public := chi.NewRouter()
	h.MountPublic(public)
	return &spSide{auth: authSvc, handler: h, public: public}
}

// asAdmin returns organization's routes as a new admin of it.
func (s *spSide) asAdmin(t *testing.T, organization uuid.UUID) http.Handler {
	t.Helper()
	return dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), s.handler.Mount)
}

// connect has organization's admin create an active connection to idp over HTTP.
func (s *spSide) connect(t *testing.T, organization uuid.UUID, idp *upstreamIdP) Connection {
	t.Helper()
	rec := dbtest.Do(t, s.asAdmin(t, organization), http.MethodPost, "/organizations/"+organization.String()+"/saml", map[string]any{
		"name": "Okta", "idp_entity_id": idp.entityID, "idp_sso_url": upstreamSSO, "idp_certificate": idp.certPEM,
		"email_attribute": "email", "name_attribute": "name", "status": "active",
	})
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create the connection: %d %s", rec.Code, rec.Body.String())
	}
	return conn
}

// begin starts a sign-in through connID as a browser and returns the ID of
// the AuthnRequest sent to the IdP.
func (s *spSide) begin(t *testing.T, connID uuid.UUID) string {
	t.Helper()
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/saml/login/"+connID.String()+"?relay=state-1", nil))
	location, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || !strings.HasPrefix(location.String(), upstreamSSO+"?") {
		t.Fatalf("login: %d %s %s; want a redirect to the IdP", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	ar, err := decodeAuthnRequest(location.Query().Get("SAMLRequest"), http.MethodGet)
	if err != nil {
		t.Fatalf("decode the AuthnRequest: %v", err)
	}
	if ar.Issuer != spEntityID(testPublicBase, connID) || ar.AssertionConsumerServiceURL != acsURL(testPublicBase, connID) ||
		location.Query().Get("RelayState") != "state-1" {
		t.Fatalf("AuthnRequest %+v, relay %q; want this connection's entity and ACS", ar, location.Query().Get("RelayState"))
	}
	return ar.ID
}

// post sends samlResponse to connID's ACS as the browser's form POST.
func (s *spSide) post(t *testing.T, connID uuid.UUID, samlResponse string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {"state-1"}}
	req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, "/saml/acs/"+connID.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.send(req)
}

// exchange trades a one-time login code at /saml/exchange.
func (s *spSide) exchange(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	return dbtest.Do(t, s.public, http.MethodPost, "/saml/exchange", map[string]string{"code": code})
}

// signIn runs a whole SP-initiated sign-in through connID, the IdP asserting
// a, and returns the token pair it buys.
func (s *spSide) signIn(t *testing.T, idp *upstreamIdP, connID uuid.UUID, a answer) auth.TokenPair {
	t.Helper()
	a.inResponseTo = s.begin(t, connID)
	code := loginCode(t, s.post(t, connID, idp.respond(t, connID, a)))
	rec := s.exchange(t, code)
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	return pair
}

// verify marks the account's address as proved.
func verify(t *testing.T, userID uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
}

// newOwner makes a new owner of organization.
func newOwner(t *testing.T, organization uuid.UUID) dbtest.Account {
	t.Helper()
	var ownerRole uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true)
		ON CONFLICT (organization_id, LOWER(name)) DO UPDATE SET is_system = true RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	a := dbtest.User(t, organization, organization)
	dbtest.Assign(t, a.ID, organization, ownerRole)
	return a
}

// linkOwner makes a new owner of organization whose account is linked to connection
// conn, as an account single sign-on created and an owner later promoted is.
func linkOwner(t *testing.T, organization, conn uuid.UUID) dbtest.Account {
	t.Helper()
	a := newOwner(t, organization)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject) VALUES ($1, $2, 'saml', $3, $4)`,
		a.ID, organization, conn, dbtest.Unique("okta|owner")); err != nil {
		t.Fatal(err)
	}
	return a
}
