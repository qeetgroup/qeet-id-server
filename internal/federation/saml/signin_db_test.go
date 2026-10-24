//go:build integration

package saml

// Database tests for SP-initiated SAML sign-in: an organisation's external IdP,
// built here with its own signing key, answers the AuthnRequest /saml/login
// sends it, and /saml/acs and /saml/exchange turn its assertion into a session.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	testAppBase   = "https://console.example.test"           // where the ACS hands a sign-in
	upstreamSSO   = "https://idp.example.test/sso"           // the upstream IdP's SSO endpoint
	callbackStart = testAppBase + "/sso/callback#saml_code=" // an accepted assertion's redirect, before the code
)

// upstreamIdP is an organisation's external identity provider, signing what it
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

// spSide is the SAML service provider, its auth service and public routes.
type spSide struct {
	auth    *auth.Service
	handler *Handler
	public  chi.Router
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

// asAdmin returns tenant's routes as a new admin of it.
func (s *spSide) asAdmin(t *testing.T, tenant uuid.UUID) http.Handler {
	t.Helper()
	return dbtest.Serve(dbtest.Principal(dbtest.User(t, tenant, tenant).ID, tenant), s.handler.Mount)
}

// connect has tenant's admin create an active connection to idp over HTTP.
func (s *spSide) connect(t *testing.T, tenant uuid.UUID, idp *upstreamIdP) Connection {
	t.Helper()
	rec := dbtest.Do(t, s.asAdmin(t, tenant), http.MethodPost, "/tenants/"+tenant.String()+"/saml", map[string]any{
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
	rec := dbtest.Do(t, s.public, http.MethodGet, "/saml/login/"+connID.String()+"?relay=state-1", nil)
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
	rec := httptest.NewRecorder()
	s.public.ServeHTTP(rec, req)
	return rec
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

// loginCode returns the one-time code an accepted assertion hands the console.
func loginCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, callbackStart) || len(location) == len(callbackStart) {
		t.Fatalf("ACS: %d %s %s; want the console's callback with a code", rec.Code, location, rec.Body.String())
	}
	return strings.TrimPrefix(location, callbackStart)
}

// verify marks the account's address as proved.
func verify(t *testing.T, userID uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
}

// sessionTenant returns the organisation a session was issued in.
func sessionTenant(t *testing.T, sessionID uuid.UUID) uuid.UUID {
	t.Helper()
	var tenant uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT tenant_id FROM auth.sessions WHERE id = $1`, sessionID).Scan(&tenant); err != nil {
		t.Fatalf("session %s: %v", sessionID, err)
	}
	return tenant
}

// TestSAMLSignIn checks that the IdP's signed answer to this connection's
// AuthnRequest buys a session in the organisation through a one-time code,
// that the answer and the code are each accepted once, that the subject stays
// linked to its person, and that a newcomer is provisioned into the organisation.
func TestSAMLSignIn(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	member := dbtest.User(t, tenant, tenant)
	verify(t, member.ID)

	meta := dbtest.Do(t, sp.public, http.MethodGet, "/saml/metadata/"+conn.ID.String(), nil)
	if meta.Code != http.StatusOK || !strings.Contains(meta.Body.String(), `entityID="`+spEntityID(testPublicBase, conn.ID)+`"`) ||
		!strings.Contains(meta.Body.String(), `Location="`+acsURL(testPublicBase, conn.ID)+`"`) {
		t.Errorf("metadata: %d %s; want this connection's entity and ACS", meta.Code, meta.Body.String())
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/metadata/"+uuid.NewString(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("metadata of an unknown connection: %d, want 404", rec.Code)
	}

	requestID := sp.begin(t, conn.ID)
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.saml_authn_requests WHERE request_id = $1 AND connection_id = $2`, requestID, conn.ID); n != 1 {
		t.Fatalf("%d AuthnRequests recorded for the connection, want 1", n)
	}
	response := idp.respond(t, conn.ID, answer{inResponseTo: requestID, nameID: "okta|asha", email: strings.ToUpper(member.Email)})
	code := loginCode(t, sp.post(t, conn.ID, response))
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.saml_authn_requests WHERE request_id = $1`, requestID); n != 0 {
		t.Errorf("the answered AuthnRequest is still open")
	}
	rec := sp.exchange(t, code)
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.UserID != member.ID || pair.AccessToken == "" || sessionTenant(t, pair.SessionID) != tenant {
		t.Fatalf("exchange: %d %s; want a session for the member in the organisation", rec.Code, rec.Body.String())
	}
	if rec := sp.exchange(t, code); !strings.Contains(rec.Body.String(), errs.CodeSAMLLoginCodeUsed) {
		t.Errorf("a one-time code used again: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLLoginCodeUsed)
	}
	if rec := sp.post(t, conn.ID, response); !strings.Contains(rec.Body.String(), errs.CodeSAMLReplayDetected) {
		t.Errorf("the same answer posted again: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLReplayDetected)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1 AND tenant_id = $2 AND provider = 'saml' AND subject = 'okta|asha'`, member.ID, tenant); n != 1 {
		t.Errorf("%d identities linked for the member, want 1", n)
	}
	var got Connection
	dbtest.Decode(t, dbtest.Do(t, sp.asAdmin(t, tenant), http.MethodGet, "/tenants/"+tenant.String()+"/saml/"+conn.ID.String(), nil), &got)
	if got.LastLoginAt == nil {
		t.Error("the connection's last sign-in was not recorded")
	}

	// The linked subject signs in the same person, whatever address it asserts.
	if again := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|asha", email: dbtest.Unique("renamed") + "@example.test"}); again.UserID != member.ID {
		t.Errorf("the linked subject signed in %s, want the member %s", again.UserID, member.ID)
	}

	newcomer := dbtest.Unique("newcomer") + "@example.test"
	joined := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|newcomer", email: newcomer})
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND tenant_id = $2 AND email = $3 AND email_verified_at IS NOT NULL AND display_name = 'Asha Rao'`, joined.UserID, tenant, newcomer); n != 1 {
		t.Errorf("the newcomer was not provisioned into the organisation, verified and named")
	}
	if sessionTenant(t, joined.SessionID) != tenant {
		t.Errorf("the newcomer's session is not in the organisation")
	}

	for name, c := range map[string]string{
		errs.CodeSAMLLoginCodeRequired: "",
		errs.CodeSAMLLoginCodeInvalid:  "not-a-code",
	} {
		if rec := sp.exchange(t, c); !strings.Contains(rec.Body.String(), name) {
			t.Errorf("exchange %q: %d %s, want %s", c, rec.Code, rec.Body.String(), name)
		}
	}
	stale := loginCode(t, sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|asha", email: member.Email})))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE auth.saml_login_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE code_hash = $1`, codes.Hash(stale)); err != nil {
		t.Fatal(err)
	}
	if rec := sp.exchange(t, stale); !strings.Contains(rec.Body.String(), errs.CodeSAMLLoginCodeExpired) {
		t.Errorf("an expired code: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLLoginCodeExpired)
	}
}

// TestSAMLIdPInitiatedSignIn checks that an unsolicited assertion is refused
// until the connection opts in, and is then accepted once only.
func TestSAMLIdPInitiatedSignIn(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	member := dbtest.User(t, tenant, tenant)
	verify(t, member.ID)

	unsolicited := idp.respond(t, conn.ID, answer{email: member.Email, signResponse: true})
	if rec := sp.post(t, conn.ID, unsolicited); !strings.Contains(rec.Body.String(), errs.CodeSAMLRequestCorrelation) {
		t.Errorf("an unsolicited assertion without the opt-in: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLRequestCorrelation)
	}
	admin := sp.asAdmin(t, tenant)
	if rec := dbtest.Do(t, admin, http.MethodPatch, "/tenants/"+tenant.String()+"/saml/"+conn.ID.String(), map[string]any{"allow_idp_initiated": true}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allow_idp_initiated":true`) {
		t.Fatalf("opt in: %d %s", rec.Code, rec.Body.String())
	}
	rec := sp.exchange(t, loginCode(t, sp.post(t, conn.ID, unsolicited)))
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.UserID != member.ID {
		t.Errorf("exchange: %d %s; want a session for the member", rec.Code, rec.Body.String())
	}
	if rec := sp.post(t, conn.ID, unsolicited); !strings.Contains(rec.Body.String(), errs.CodeSAMLReplayDetected) {
		t.Errorf("the unsolicited assertion posted again: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLReplayDetected)
	}
}

// TestSAMLAssertionRefused checks that the ACS issues no login code for an
// answer that is unsigned, signed by another key, altered or wrapped after
// signing, from another issuer, meant for another audience, recipient or
// destination, outside its validity period, uncorrelated, or without an
// address, nor through a disabled, misconfigured or unknown connection.
func TestSAMLAssertionRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp, impostor := newUpstreamIdP(t), newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	member := dbtest.User(t, tenant, tenant)
	victim := dbtest.User(t, tenant, tenant)
	verify(t, member.ID)
	verify(t, victim.ID)
	now := time.Now().UTC()
	issued := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.saml_login_codes WHERE tenant_id = $1`, tenant)
	}

	renameSubject := func(el *etree.Element) {
		for _, value := range append(el.FindElements(".//NameID"), el.FindElements(".//AttributeValue")...) {
			if value.Text() == member.Email {
				value.SetText(victim.Email)
			}
		}
	}
	// wrap puts an unsigned copy of the signed assertion, naming the victim,
	// ahead of it. goxmldsig leaves child indexes stale, so Signature is
	// filtered out of the copy rather than removed.
	wrap := func(response *etree.Element) {
		signed := response.FindElement("./Assertion")
		forged := signed.Copy()
		kept := forged.Child[:0]
		for _, tok := range forged.Child {
			if el, ok := tok.(*etree.Element); !ok || el.Tag != "Signature" {
				kept = append(kept, tok)
			}
		}
		forged.Child = kept
		forged.CreateAttr("ID", "_"+uuid.NewString())
		renameSubject(forged)
		response.InsertChildAt(signed.Index(), forged)
	}
	for _, c := range []struct {
		name string
		a    answer
		want string
	}{
		{"an unsigned assertion", answer{unsigned: true}, errs.CodeSAMLAssertionInvalid},
		{"an assertion signed by another key", answer{signer: impostor.signer}, errs.CodeSAMLAssertionInvalid},
		{"an assertion altered after signing", answer{edit: renameSubject}, errs.CodeSAMLAssertionInvalid},
		{"a signed response altered after signing", answer{signResponse: true, edit: renameSubject}, errs.CodeSAMLAssertionInvalid},
		{"a forged assertion ahead of a signed one", answer{edit: wrap}, errs.CodeSAMLAssertionInvalid},
		{"another issuer", answer{issuer: impostor.entityID}, errs.CodeSAMLAssertionInvalid},
		{"another audience", answer{audience: "https://other-sp.example.test"}, errs.CodeSAMLAssertionConditions},
		{"another recipient", answer{recipient: acsURL(testPublicBase, uuid.New())}, errs.CodeSAMLAssertionInvalid},
		{"another destination", answer{destination: "https://evil.example.test/acs"}, errs.CodeSAMLAssertionInvalid},
		{"an expired assertion", answer{notBefore: now.Add(-10 * time.Minute), notOnOrAfter: now.Add(-5 * time.Minute)}, errs.CodeSAMLAssertionInvalid},
		{"an assertion not yet valid", answer{notBefore: now.Add(5 * time.Minute), notOnOrAfter: now.Add(10 * time.Minute)}, errs.CodeSAMLAssertionConditions},
		{"an answer to a request never sent", answer{inResponseTo: "_never-sent"}, errs.CodeSAMLRequestCorrelation},
		{"no address", answer{nameID: " "}, errs.CodeSAMLAssertionNoEmail},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := issued()
			a := c.a
			if a.email == "" && a.nameID == "" {
				a.email = member.Email
			}
			requestID := sp.begin(t, conn.ID)
			if a.inResponseTo == "" {
				a.inResponseTo = requestID
			}
			rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, a))
			if rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), c.want) {
				t.Errorf("%s: %d %s, want %s", c.name, rec.Code, rec.Body.String(), c.want)
			}
			if issued() != before {
				t.Errorf("%s: a login code was issued", c.name)
			}
		})
	}

	before := issued()
	expired := sp.begin(t, conn.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.saml_authn_requests SET expires_at = NOW() - INTERVAL '1 second' WHERE request_id = $1`, expired); err != nil {
		t.Fatal(err)
	}
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: expired, email: member.Email})); !strings.Contains(rec.Body.String(), errs.CodeSAMLRequestCorrelation) {
		t.Errorf("an answer to an expired request: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLRequestCorrelation)
	}
	if rec := sp.post(t, conn.ID, ""); !strings.Contains(rec.Body.String(), errs.CodeSAMLResponseMissing) {
		t.Errorf("no SAMLResponse: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLResponseMissing)
	}
	if rec := sp.post(t, conn.ID, "%%%not-base64%%%"); !strings.Contains(rec.Body.String(), errs.CodeSAMLAssertionInvalid) {
		t.Errorf("an unreadable SAMLResponse: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLAssertionInvalid)
	}
	if rec := sp.post(t, uuid.New(), idp.respond(t, conn.ID, answer{email: member.Email})); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown connection's ACS: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/not-a-uuid", nil); !strings.Contains(rec.Body.String(), errs.CodeSAMLIDInvalid) {
		t.Errorf("login with a malformed connection ID: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLIDInvalid)
	}

	pending := sp.begin(t, conn.ID)
	if rec := dbtest.Do(t, sp.asAdmin(t, tenant), http.MethodPatch, "/tenants/"+tenant.String()+"/saml/"+conn.ID.String(), map[string]any{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/"+conn.ID.String(), nil); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionDisabled) {
		t.Errorf("login through a disabled connection: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionDisabled)
	}
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: pending, email: member.Email})); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionDisabled) {
		t.Errorf("an answer through a disabled connection: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionDisabled)
	}

	// A connection stored before today's checks: a plain-http SSO URL, then an
	// unreadable certificate.
	broken := sp.connect(t, tenant, idp)
	pending = sp.begin(t, broken.ID)
	for _, change := range []string{
		`UPDATE tenant.saml_connections SET idp_sso_url = 'http://idp.example.test/sso' WHERE id = $1`,
		`UPDATE tenant.saml_connections SET idp_sso_url = '` + upstreamSSO + `', idp_certificate = 'not a certificate' WHERE id = $1`,
	} {
		if _, err := dbtest.Pool(t).Exec(ctx, change, broken.ID); err != nil {
			t.Fatal(err)
		}
		if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/"+broken.ID.String(), nil); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionMisconfigured) {
			t.Errorf("login through a misconfigured connection: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionMisconfigured)
		}
	}
	if rec := sp.post(t, broken.ID, idp.respond(t, broken.ID, answer{inResponseTo: pending, email: member.Email})); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionMisconfigured) {
		t.Errorf("an answer through a connection without a readable certificate: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionMisconfigured)
	}
	if issued() != before {
		t.Error("a refused answer was issued a login code")
	}
}

// TestSAMLSignInAcrossOrganisations checks that one organisation's connection
// accepts neither an answer meant for another organisation's connection to the
// same IdP, nor one to a request that connection made, and adopts no account
// of another organisation; and that a suspended person buys no session.
func TestSAMLSignInAcrossOrganisations(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	conn, otherConn := sp.connect(t, tenant, idp), sp.connect(t, other, idp)
	member := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, other, other)
	verify(t, member.ID)
	verify(t, outsider.ID)
	issued := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.saml_login_codes WHERE user_id IN ($1, $2)`, member.ID, outsider.ID)
	}
	before := issued()

	forOther := idp.respond(t, otherConn.ID, answer{inResponseTo: sp.begin(t, otherConn.ID), email: member.Email})
	if rec := sp.post(t, conn.ID, forOther); rec.Code == http.StatusFound {
		t.Errorf("an answer meant for another organisation's connection: %d, want refused", rec.Code)
	}
	otherRequest := idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, otherConn.ID), email: member.Email})
	if rec := sp.post(t, conn.ID, otherRequest); !strings.Contains(rec.Body.String(), errs.CodeSAMLRequestCorrelation) {
		t.Errorf("an answer to another organisation's request: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLRequestCorrelation)
	}
	takeover := idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|outsider", email: outsider.Email})
	if rec := sp.post(t, conn.ID, takeover); rec.Code == http.StatusFound {
		t.Errorf("an assertion of another organisation's account: %d, want refused", rec.Code)
	}
	if issued() != before {
		t.Error("a refused answer was issued a login code")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, outsider.ID); n != 0 {
		t.Errorf("another organisation's account was linked to the connection")
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: member.Email}))
	if rec.Code == http.StatusFound {
		if rec := sp.exchange(t, loginCode(t, rec)); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), errs.CodeAuthAccountInactive) {
			t.Errorf("a suspended account's sign-in: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeAuthAccountInactive)
		}
	}
}

// TestSAMLNamesAnotherOrganisationsAccount checks that the refusal of another
// organisation's account says why.
func TestSAMLNamesAnotherOrganisationsAccount(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	outsider := dbtest.User(t, other, other)
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: outsider.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeSAMLUserTenantMismatch) {
		t.Errorf("an assertion of another organisation's account: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeSAMLUserTenantMismatch)
	}
}

// TestSAMLDoesNotAdoptAnUnverifiedAccount checks that an assertion does not
// adopt an account whose address was never proved, so whoever registered it
// can't keep a password on the IdP user's account.
func TestSAMLDoesNotAdoptAnUnverifiedAccount(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	squatted := dbtest.User(t, tenant)
	dbtest.SetPassword(t, squatted.ID, "squatter-password")
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|real-owner", email: squatted.Email}))
	if rec.Code == http.StatusFound {
		t.Errorf("an assertion of an unverified account with a password: %d, want refused", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, squatted.ID); n != 0 {
		t.Errorf("the IdP user was linked to the squatted account")
	}
}

// TestSAMLLinkSignsInOnlyHomeAccounts checks that a subject linked to an
// account signs it in only while this organisation is the account's home, so a
// link made before the account moved, or for a guest, signs nobody in.
func TestSAMLLinkSignsInOnlyHomeAccounts(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant, home := dbtest.Tenant(t), dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	guest := dbtest.User(t, home, home, tenant)
	verify(t, guest.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email) VALUES ($1, $2, 'saml', 'okta|guest', $3)
	`, guest.ID, tenant, guest.Email); err != nil {
		t.Fatal(err)
	}
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|guest", email: guest.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeSAMLUserTenantMismatch) {
		t.Errorf("a linked subject of a guest whose home is elsewhere: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeSAMLUserTenantMismatch)
	}
}

// TestSAMLRefusesAGuest checks that an organisation's IdP can't vouch for a
// guest member whose home is another organisation, so its session can't be
// switched into the guest's home.
func TestSAMLRefusesAGuest(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	tenant, home := dbtest.Tenant(t), dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	guest := dbtest.User(t, home, home, tenant)
	verify(t, guest.ID)
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "attacker-controlled", email: guest.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeSAMLUserTenantMismatch) {
		t.Errorf("an assertion of a guest whose home is elsewhere: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeSAMLUserTenantMismatch)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, guest.ID); n != 0 {
		t.Errorf("the guest was linked to the organisation's IdP")
	}
}
