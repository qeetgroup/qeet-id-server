//go:build integration

package saml

// Database tests for SP-initiated SAML sign-in: an organization's external IdP,
// built here with its own signing key, answers the AuthnRequest /saml/login
// sends it, and /saml/acs and /saml/exchange turn its assertion into a session.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// loginCode returns the one-time code an accepted assertion hands the console.
func loginCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, callbackStart) || len(location) == len(callbackStart) {
		t.Fatalf("ACS: %d %s %s; want the console's callback with a code", rec.Code, location, rec.Body.String())
	}
	return strings.TrimPrefix(location, callbackStart)
}

// sessionOrganization returns the organization a session was issued in.
func sessionOrganization(t *testing.T, sessionID uuid.UUID) uuid.UUID {
	t.Helper()
	var organization uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT organization_id FROM auth.sessions WHERE id = $1`, sessionID).Scan(&organization); err != nil {
		t.Fatalf("session %s: %v", sessionID, err)
	}
	return organization
}

// TestSAMLSignIn checks that the IdP's signed answer to this connection's
// AuthnRequest buys a session in the organization through a one-time code,
// that the answer and the code are each accepted once, that the subject stays
// linked to its person, and that a newcomer is provisioned into the
// organization only while its domain has just-in-time provisioning on, which an
// existing member's adoption doesn't need.
func TestSAMLSignIn(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	domain := dbtest.Domain(t, organization)
	setJIT := func(on bool) {
		t.Helper()
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.domains SET jit_enabled = $2 WHERE organization_id = $1`, organization, on); err != nil {
			t.Fatal(err)
		}
	}
	setJIT(false)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
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
	var pair authentication.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.UserID != member.ID || pair.AccessToken == "" || sessionOrganization(t, pair.SessionID) != organization {
		t.Fatalf("exchange: %d %s; want a session for the member in the organization", rec.Code, rec.Body.String())
	}
	if rec := sp.exchange(t, code); !strings.Contains(rec.Body.String(), CodeLoginCodeUsed) {
		t.Errorf("a one-time code used again: %d %s, want %s", rec.Code, rec.Body.String(), CodeLoginCodeUsed)
	}
	if rec := sp.post(t, conn.ID, response); !strings.Contains(rec.Body.String(), CodeReplayDetected) {
		t.Errorf("the same answer posted again: %d %s, want %s", rec.Code, rec.Body.String(), CodeReplayDetected)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND organization_id = $2 AND provider = 'saml' AND connection_id = $3 AND subject = 'okta|asha'`, member.ID, organization, conn.ID); n != 1 {
		t.Errorf("%d identities linked for the member to the connection, want 1", n)
	}
	var got Connection
	dbtest.Decode(t, dbtest.Do(t, sp.asAdmin(t, organization), http.MethodGet, "/organizations/"+organization.String()+"/saml/"+conn.ID.String(), nil), &got)
	if got.LastLoginAt == nil {
		t.Error("the connection's last sign-in was not recorded")
	}

	// The linked subject signs in the same person, whatever address it asserts.
	if again := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|asha", email: dbtest.Unique("renamed") + "@example.test"}); again.UserID != member.ID {
		t.Errorf("the linked subject signed in %s, want the member %s", again.UserID, member.ID)
	}

	newcomer := dbtest.Unique("newcomer") + "@" + domain
	rec = sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|newcomer", email: newcomer}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeJITNotAllowed) {
		t.Errorf("a newcomer while the domain has JIT off: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeJITNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, newcomer); n != 0 {
		t.Fatal("a newcomer was provisioned while the domain has JIT off")
	}
	setJIT(true)
	joined := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|newcomer", email: newcomer})
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2 AND email = $3 AND email_verified_at IS NOT NULL AND display_name = 'Asha Rao'`, joined.UserID, organization, newcomer); n != 1 {
		t.Errorf("the newcomer was not provisioned into the organization, verified and named")
	}
	if sessionOrganization(t, joined.SessionID) != organization {
		t.Errorf("the newcomer's session is not in the organization")
	}

	for name, c := range map[string]string{
		CodeLoginCodeRequired: "",
		CodeLoginCodeInvalid:  "not-a-code",
	} {
		if rec := sp.exchange(t, c); !strings.Contains(rec.Body.String(), name) {
			t.Errorf("exchange %q: %d %s, want %s", c, rec.Code, rec.Body.String(), name)
		}
	}
	stale := loginCode(t, sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|asha", email: member.Email})))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE auth.login_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE code_hash = $1`, codes.Hash(stale)); err != nil {
		t.Fatal(err)
	}
	if rec := sp.exchange(t, stale); !strings.Contains(rec.Body.String(), CodeLoginCodeExpired) {
		t.Errorf("an expired code: %d %s, want %s", rec.Code, rec.Body.String(), CodeLoginCodeExpired)
	}
}

// TestSAMLIdPInitiatedSignIn checks that an unsolicited assertion is refused
// until the connection opts in, and is then accepted once only.
func TestSAMLIdPInitiatedSignIn(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)

	unsolicited := idp.respond(t, conn.ID, answer{email: member.Email, signResponse: true})
	if rec := sp.post(t, conn.ID, unsolicited); !strings.Contains(rec.Body.String(), CodeRequestCorrelation) {
		t.Errorf("an unsolicited assertion without the opt-in: %d %s, want %s", rec.Code, rec.Body.String(), CodeRequestCorrelation)
	}
	admin := sp.asAdmin(t, organization)
	if rec := dbtest.Do(t, admin, http.MethodPatch, "/organizations/"+organization.String()+"/saml/"+conn.ID.String(), map[string]any{"allow_idp_initiated": true}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allow_idp_initiated":true`) {
		t.Fatalf("opt in: %d %s", rec.Code, rec.Body.String())
	}
	rec := sp.exchange(t, loginCode(t, sp.post(t, conn.ID, unsolicited)))
	var pair authentication.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.UserID != member.ID {
		t.Errorf("exchange: %d %s; want a session for the member", rec.Code, rec.Body.String())
	}
	if rec := sp.post(t, conn.ID, unsolicited); !strings.Contains(rec.Body.String(), CodeReplayDetected) {
		t.Errorf("the unsolicited assertion posted again: %d %s, want %s", rec.Code, rec.Body.String(), CodeReplayDetected)
	}
}

// TestReplayIDOutlivesItsAssertion checks that an assertion valid for longer
// than a day can't be replayed once a day has passed: its IDs are kept until
// it expires, beyond the sweep of the usual ones.
func TestReplayIDOutlivesItsAssertion(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	if rec := dbtest.Do(t, sp.asAdmin(t, organization), http.MethodPatch, "/organizations/"+organization.String()+"/saml/"+conn.ID.String(), map[string]any{"allow_idp_initiated": true}); rec.Code != http.StatusOK {
		t.Fatalf("opt in: %d %s", rec.Code, rec.Body.String())
	}
	longLived := idp.respond(t, conn.ID, answer{email: member.Email, signResponse: true, notOnOrAfter: time.Now().UTC().Add(72 * time.Hour)})
	loginCode(t, sp.post(t, conn.ID, longLived))

	// A day and an hour later, with the expired IDs swept.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.saml_replay_ids SET expires_at = expires_at - INTERVAL '25 hours' WHERE connection_id = $1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM auth.saml_replay_ids WHERE connection_id = $1 AND expires_at <= NOW()`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if rec := sp.post(t, conn.ID, longLived); !strings.Contains(rec.Body.String(), CodeReplayDetected) {
		t.Errorf("the assertion posted again a day later, still valid: %d %s, want %s", rec.Code, rec.Body.String(), CodeReplayDetected)
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
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.User(t, organization, organization)
	victim := dbtest.User(t, organization, organization)
	verify(t, member.ID)
	verify(t, victim.ID)
	now := time.Now().UTC()
	issued := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE organization_id = $1`, organization)
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
		{"another audience", answer{audience: "https://other-sp.example.test"}, CodeAssertionConditions},
		{"another recipient", answer{recipient: acsURL(testPublicBase, uuid.New())}, errs.CodeSAMLAssertionInvalid},
		{"another destination", answer{destination: "https://evil.example.test/acs"}, errs.CodeSAMLAssertionInvalid},
		{"an expired assertion", answer{notBefore: now.Add(-10 * time.Minute), notOnOrAfter: now.Add(-5 * time.Minute)}, errs.CodeSAMLAssertionInvalid},
		{"an assertion not yet valid", answer{notBefore: now.Add(5 * time.Minute), notOnOrAfter: now.Add(10 * time.Minute)}, CodeAssertionConditions},
		{"an answer to a request never sent", answer{inResponseTo: "_never-sent"}, CodeRequestCorrelation},
		{"no address", answer{nameID: " "}, CodeAssertionNoEmail},
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
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: expired, email: member.Email})); !strings.Contains(rec.Body.String(), CodeRequestCorrelation) {
		t.Errorf("an answer to an expired request: %d %s, want %s", rec.Code, rec.Body.String(), CodeRequestCorrelation)
	}
	if rec := sp.post(t, conn.ID, ""); !strings.Contains(rec.Body.String(), CodeResponseMissing) {
		t.Errorf("no SAMLResponse: %d %s, want %s", rec.Code, rec.Body.String(), CodeResponseMissing)
	}
	if rec := sp.post(t, conn.ID, "%%%not-base64%%%"); !strings.Contains(rec.Body.String(), errs.CodeSAMLAssertionInvalid) {
		t.Errorf("an unreadable SAMLResponse: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLAssertionInvalid)
	}
	if rec := sp.post(t, uuid.New(), idp.respond(t, conn.ID, answer{email: member.Email})); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown connection's ACS: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/not-a-uuid", nil); !strings.Contains(rec.Body.String(), CodeIDInvalid) {
		t.Errorf("login with a malformed connection ID: %d %s, want %s", rec.Code, rec.Body.String(), CodeIDInvalid)
	}

	pending := sp.begin(t, conn.ID)
	if rec := dbtest.Do(t, sp.asAdmin(t, organization), http.MethodPatch, "/organizations/"+organization.String()+"/saml/"+conn.ID.String(), map[string]any{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/"+conn.ID.String(), nil); !strings.Contains(rec.Body.String(), CodeConnectionDisabled) {
		t.Errorf("login through a disabled connection: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionDisabled)
	}
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: pending, email: member.Email})); !strings.Contains(rec.Body.String(), CodeConnectionDisabled) {
		t.Errorf("an answer through a disabled connection: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionDisabled)
	}

	// A connection stored before today's checks: a plain-http SSO URL, then an
	// unreadable certificate.
	broken := sp.connect(t, organization, idp)
	pending = sp.begin(t, broken.ID)
	for _, change := range []string{
		`UPDATE organization.saml_connections SET idp_sso_url = 'http://idp.example.test/sso' WHERE id = $1`,
		`WITH sso AS (UPDATE organization.saml_connections SET idp_sso_url = '` + upstreamSSO + `' WHERE id = $1)
		 UPDATE organization.saml_connection_certificates SET certificate = 'not a certificate' WHERE connection_id = $1`,
	} {
		if _, err := dbtest.Pool(t).Exec(ctx, change, broken.ID); err != nil {
			t.Fatal(err)
		}
		if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/"+broken.ID.String(), nil); !strings.Contains(rec.Body.String(), CodeConnectionMisconfigured) {
			t.Errorf("login through a misconfigured connection: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionMisconfigured)
		}
	}
	if rec := sp.post(t, broken.ID, idp.respond(t, broken.ID, answer{inResponseTo: pending, email: member.Email})); !strings.Contains(rec.Body.String(), CodeConnectionMisconfigured) {
		t.Errorf("an answer through a connection without a readable certificate: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionMisconfigured)
	}
	if issued() != before {
		t.Error("a refused answer was issued a login code")
	}
}

// TestSAMLSignInAcrossOrganizations checks that one organization's connection
// accepts neither an answer meant for another organization's connection to the
// same IdP, nor one to a request that connection made, and adopts no account
// of another organization; and that a suspended person buys no session.
func TestSAMLSignInAcrossOrganizations(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	conn, otherConn := sp.connect(t, organization, idp), sp.connect(t, other, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	outsider := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, other), other, other)
	verify(t, member.ID)
	verify(t, outsider.ID)
	issued := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id IN ($1, $2)`, member.ID, outsider.ID)
	}
	before := issued()

	forOther := idp.respond(t, otherConn.ID, answer{inResponseTo: sp.begin(t, otherConn.ID), email: member.Email})
	if rec := sp.post(t, conn.ID, forOther); rec.Code == http.StatusFound {
		t.Errorf("an answer meant for another organization's connection: %d, want refused", rec.Code)
	}
	otherRequest := idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, otherConn.ID), email: member.Email})
	if rec := sp.post(t, conn.ID, otherRequest); !strings.Contains(rec.Body.String(), CodeRequestCorrelation) {
		t.Errorf("an answer to another organization's request: %d %s, want %s", rec.Code, rec.Body.String(), CodeRequestCorrelation)
	}
	takeover := idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|outsider", email: outsider.Email})
	if rec := sp.post(t, conn.ID, takeover); rec.Code == http.StatusFound {
		t.Errorf("an assertion of another organization's account: %d, want refused", rec.Code)
	}
	if issued() != before {
		t.Error("a refused answer was issued a login code")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, outsider.ID); n != 0 {
		t.Errorf("another organization's account was linked to the connection")
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: member.Email}))
	if rec.Code == http.StatusFound {
		if rec := sp.exchange(t, loginCode(t, rec)); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), errs.CodeAuthAccountInactive) {
			t.Errorf("a suspended account's sign-in: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeAuthAccountInactive)
		}
	}
}

// TestSAMLNamesAnotherOrganizationsAccount checks that the refusal of another
// organization's account on the organization's own domain says why.
func TestSAMLNamesAnotherOrganizationsAccount(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	outsider := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), other, other)
	verify(t, outsider.ID)
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: outsider.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeUserOrganizationMismatch) {
		t.Errorf("an assertion of another organization's account: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeUserOrganizationMismatch)
	}
}

// TestSAMLDoesNotAdoptAnUnverifiedAccount checks that an assertion does not
// adopt an account whose address was never proved, so whoever registered it
// can't keep a password on the IdP user's account.
func TestSAMLDoesNotAdoptAnUnverifiedAccount(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	squatted := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization)
	dbtest.SetPassword(t, squatted.ID, "squatter-password")
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|real-owner", email: squatted.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeAccountUnverified) {
		t.Errorf("an assertion of an unverified account with a password: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeAccountUnverified)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, squatted.ID); n != 0 {
		t.Errorf("the IdP user was linked to the squatted account")
	}
}

// TestSAMLLinkSignsInOnlyHomeAccounts checks that a subject linked to an
// account signs it in only while this organization is the account's home, so a
// link made before the account moved, or for a guest, signs nobody in.
func TestSAMLLinkSignsInOnlyHomeAccounts(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	guest := dbtest.User(t, home, home, organization)
	verify(t, guest.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email) VALUES ($1, $2, 'saml', $3, 'okta|guest', $4)
	`, guest.ID, organization, conn.ID, guest.Email); err != nil {
		t.Fatal(err)
	}
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "okta|guest", email: guest.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeUserOrganizationMismatch) {
		t.Errorf("a linked subject of a guest whose home is elsewhere: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeUserOrganizationMismatch)
	}
}

// TestSAMLSignInNeedsSSOInThePlan checks that a connection can be set up only
// on a plan with SSO, and that one set up while the plan had it signs no one
// in once the plan has lapsed: neither the redirect to the IdP nor its answer.
func TestSAMLSignInNeedsSSOInThePlan(t *testing.T) {
	paid, free := dbtest.Organization(t), dbtest.Organization(t)
	allowed := map[uuid.UUID]bool{paid: true}
	sp := newSPSide(t, func(d *Deps) { d.Gate = poolGate{pool: dbtest.Pool(t), allowed: allowed} })
	idp := newUpstreamIdP(t)

	rec := dbtest.Do(t, sp.asAdmin(t, free), http.MethodPost, "/organizations/"+free.String()+"/saml", map[string]any{
		"name": "Okta", "idp_entity_id": idp.entityID, "idp_sso_url": upstreamSSO, "idp_certificate": idp.certPEM, "status": "active",
	})
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("connection on a plan without SSO: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}

	conn := sp.connect(t, paid, idp)
	newcomer := dbtest.Unique("new") + "@" + dbtest.Domain(t, paid)
	requestID := sp.begin(t, conn.ID)
	response := idp.respond(t, conn.ID, answer{inResponseTo: requestID, nameID: "okta|lapsed", email: newcomer})

	delete(allowed, paid) // the plan lapses
	if rec := sp.post(t, conn.ID, response); rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("assertion after the plan lapsed: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/"+conn.ID.String(), nil); rec.Code != http.StatusPaymentRequired {
		t.Errorf("sign-in start after the plan lapsed: %d %s, want 402", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, newcomer); n != 0 {
		t.Errorf("the refused assertion provisioned the newcomer")
	}

	allowed[paid] = true // paid again
	if rec := sp.post(t, conn.ID, response); rec.Code != http.StatusFound {
		t.Errorf("assertion once paid again: %d %s, want the console's callback", rec.Code, rec.Body.String())
	}
}

// TestSAMLRefusesAGuest checks that an organization's IdP can't vouch for a
// guest member whose home is another organization, so its session can't be
// switched into the guest's home.
func TestSAMLRefusesAGuest(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization, home := dbtest.Organization(t), dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	guest := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), home, home, organization)
	verify(t, guest.ID)
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), nameID: "attacker-controlled", email: guest.Email}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeUserOrganizationMismatch) {
		t.Errorf("an assertion of a guest whose home is elsewhere: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeUserOrganizationMismatch)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, guest.ID); n != 0 {
		t.Errorf("the guest was linked to the organization's IdP")
	}
}

// TestSAMLSpeaksOnlyForTheOrganizationsDomains checks that a connection adopts
// or creates an account only on a domain its organization has verified, or one
// below it, and not where another organization verified a closer domain.
func TestSAMLSpeaksOnlyForTheOrganizationsDomains(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	domain := dbtest.Domain(t, organization)
	team := "team." + domain
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO organization.domains (organization_id, domain, verification_token, verified_at) VALUES ($1, $2, 'test', NOW())
	`, other, team); err != nil {
		t.Fatal(err)
	}
	member := dbtest.User(t, organization, organization)
	verify(t, member.ID)

	for name, email := range map[string]string{
		"an account on a domain nobody verified":                    member.Email,
		"a newcomer on a domain nobody verified":                    dbtest.Unique("new") + "@example.test",
		"a newcomer on another organization's domain":               dbtest.Unique("new") + "@" + dbtest.Domain(t, other),
		"a newcomer on another organization's subdomain of the own": dbtest.Unique("new") + "@" + team,
	} {
		rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: email}))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeEmailDomainUnverified) {
			t.Errorf("%s: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), CodeEmailDomainUnverified)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE organization_id = $1 AND subject = $2`, organization, email); n != 0 {
			t.Errorf("%s: the address was linked", name)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE organization_id = $1`, organization); n != 2 {
		t.Errorf("%d accounts in the organization, want its member and its admin only", n)
	}

	below := dbtest.Unique("new") + "@eu." + domain
	if joined := sp.signIn(t, idp, conn.ID, answer{email: below}); dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2 AND email = $3`, joined.UserID, organization, below) != 1 {
		t.Errorf("a newcomer below the organization's domain was not provisioned into it")
	}
}

// TestSAMLLinkBelongsToItsConnection checks that a subject linked through one
// connection signs nobody in through another connection of the organization.
func TestSAMLLinkBelongsToItsConnection(t *testing.T) {
	sp := newSPSide(t)
	idp, rogue := newUpstreamIdP(t), newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn, rogueConn := sp.connect(t, organization, idp), sp.connect(t, organization, rogue)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	if got := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|asha", email: member.Email}); got.UserID != member.ID {
		t.Fatalf("signed in %s, want the member %s", got.UserID, member.ID)
	}

	rec := sp.post(t, rogueConn.ID, rogue.respond(t, rogueConn.ID, answer{inResponseTo: sp.begin(t, rogueConn.ID), nameID: "okta|asha", email: dbtest.Unique("rogue") + "@example.test"}))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeEmailDomainUnverified) {
		t.Errorf("another connection asserting the linked subject: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeEmailDomainUnverified)
	}
}

// TestSAMLDoesNotAdoptAnAdministrator checks that an assertion adopts no
// account that owns the organization or holds an admin permission there,
// directly or through a group, and that one linked before keeps signing in.
func TestSAMLDoesNotAdoptAnAdministrator(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	domain := dbtest.Domain(t, organization)
	account := func(roles ...uuid.UUID) dbtest.Account {
		a := dbtest.UserAt(t, dbtest.Unique("user")+"@"+domain, organization)
		verify(t, a.ID)
		for _, role := range roles {
			dbtest.Assign(t, a.ID, organization, role)
		}
		return a
	}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	grouped := account()
	if _, err := pool.Exec(ctx, `
		WITH g AS (INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Identity team') RETURNING id),
		     r AS (INSERT INTO rbac.group_roles (group_id, organization_id, role_id) SELECT id, $1, $3 FROM g)
		INSERT INTO organization.group_members (group_id, user_id, organization_id) SELECT id, $2, $1 FROM g
	`, organization, grouped.ID, dbtest.Role(t, organization, "role.write")); err != nil {
		t.Fatal(err)
	}

	for name, a := range map[string]dbtest.Account{
		"an owner":                               account(ownerRole),
		"an account holding connection.write":    account(dbtest.Role(t, organization, "user.read", "connection.write")),
		"a member of a group holding role.write": grouped,
	} {
		rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: a.Email}))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeAccountAdministers) {
			t.Errorf("%s: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), CodeAccountAdministers)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, a.ID); n != 0 {
			t.Errorf("%s was linked to the connection", name)
		}
	}

	reader := account(dbtest.Role(t, organization, "user.read", "audit.read"))
	if got := sp.signIn(t, idp, conn.ID, answer{email: reader.Email}); got.UserID != reader.ID {
		t.Errorf("an account holding only read permissions: signed in %s, want %s", got.UserID, reader.ID)
	}
	dbtest.Assign(t, reader.ID, organization, dbtest.Role(t, organization, "user.write"))
	if got := sp.signIn(t, idp, conn.ID, answer{email: reader.Email}); got.UserID != reader.ID {
		t.Errorf("an administrator linked before: signed in %s, want %s", got.UserID, reader.ID)
	}
}

// TestSAMLDraftConnectionSignsNobodyIn checks that a connection still being
// set up neither starts a sign-in nor accepts an answer, until it is active.
func TestSAMLDraftConnectionSignsNobodyIn(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	pending := sp.begin(t, conn.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.saml_connections SET status = 'draft' WHERE id = $1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, sp.public, http.MethodGet, "/saml/login/"+conn.ID.String(), nil); !strings.Contains(rec.Body.String(), CodeConnectionDraft) {
		t.Errorf("start a sign-in through a draft connection: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionDraft)
	}
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: pending, email: member.Email})); !strings.Contains(rec.Body.String(), CodeConnectionDraft) {
		t.Errorf("an answer through a draft connection: %d %s, want %s", rec.Code, rec.Body.String(), CodeConnectionDraft)
	}
}

// TestSAMLAnswerCompletesOnlyInTheBrowserThatAsked checks that an answer to
// a sign-in request completes only in the browser that sent the request, so
// whoever began one can't post its answer from someone else's browser.
func TestSAMLAnswerCompletesOnlyInTheBrowserThatAsked(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	attacker := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, attacker.ID)
	response := idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: attacker.Email})

	victim := &spSide{auth: sp.auth, handler: sp.handler, public: sp.public}
	if rec := victim.post(t, conn.ID, response); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeOtherBrowser) {
		t.Errorf("the answer posted from another browser: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeOtherBrowser)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1`, attacker.ID); n != 0 {
		t.Error("an answer from another browser was issued a login code")
	}
	if got := sp.signIn(t, idp, conn.ID, answer{email: attacker.Email}); got.UserID != attacker.ID {
		t.Errorf("a sign-in begun and answered in one browser signed in %s, want %s", got.UserID, attacker.ID)
	}
}

// TestSAMLAdoptsADirectoryProvisionedAccount checks that an account the
// organization's directory provisioned, its address never proved, is adopted
// by the organization's IdP and marked verified.
func TestSAMLAdoptsADirectoryProvisionedAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	provisioned := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET provisioned_via = 'scim', email_verified_at = NULL WHERE id = $1`, provisioned.ID); err != nil {
		t.Fatal(err)
	}
	if got := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|provisioned", email: provisioned.Email}); got.UserID != provisioned.ID {
		t.Fatalf("signed in %s, want the provisioned account %s", got.UserID, provisioned.ID)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email_verified_at IS NOT NULL`, provisioned.ID); n != 1 {
		t.Error("the adopted account's address was not marked verified")
	}
}

// TestSAMLSignInSyncsGroupsAndName checks that the connection's groups
// attribute is kept, that each sign-in sets the person's display name and puts
// them in the groups their asserted groups are mapped to, takes them out once
// the IdP stops asserting them, and leaves them be when Entra ID withholds the
// groups.
func TestSAMLSignInSyncsGroupsAndName(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	admin := sp.asAdmin(t, organization)
	path := "/organizations/" + organization.String() + "/saml"
	rec := dbtest.Do(t, admin, http.MethodPost, path, map[string]any{
		"name": "Entra ID", "idp_entity_id": idp.entityID, "idp_sso_url": upstreamSSO, "idp_certificate": idp.certPEM,
		"email_attribute": "email", "name_attribute": "name", "groups_attribute": " roles ", "status": "active",
	})
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.GroupsAttribute != "roles" {
		t.Fatalf("create: %d %s; want the groups attribute kept, trimmed", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, admin, http.MethodPost, path, map[string]any{
		"name": "Too long", "idp_entity_id": idp.entityID, "idp_sso_url": upstreamSSO, "idp_certificate": idp.certPEM,
		"groups_attribute": strings.Repeat("g", 257),
	}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeValidation) {
		t.Errorf("an over-long groups attribute: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	rec = dbtest.Do(t, admin, http.MethodPatch, path+"/"+conn.ID.String(), map[string]any{"groups_attribute": ""})
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusOK || conn.GroupsAttribute != "" {
		t.Fatalf("clear the groups attribute: %d %s", rec.Code, rec.Body.String())
	}
	var listed struct{ Items []Connection }
	dbtest.Decode(t, dbtest.Do(t, admin, http.MethodGet, path, nil), &listed)
	if len(listed.Items) != 1 || listed.Items[0].GroupsAttribute != "" {
		t.Errorf("listed %+v, want the connection with no groups attribute", listed.Items)
	}

	var engineering uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Engineering') RETURNING id`, organization).Scan(&engineering); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.sso_group_mappings (organization_id, connection_id, idp_group, group_id) VALUES ($1, $2, 'eng-team', $3)`, organization, conn.ID, engineering); err != nil {
		t.Fatal(err)
	}
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	synced := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE organization_id = $1 AND group_id = $2 AND user_id = $3 AND source_connection_id = $4`,
			organization, engineering, member.ID, conn.ID)
	}

	sp.signIn(t, idp, conn.ID, answer{nameID: "entra|asha", email: member.Email,
		attributes: map[string][]string{"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": {"ENG-TEAM", "other"}}})
	if synced() != 1 {
		t.Fatal("the sign-in didn't put the person in the group their IdP group is mapped to")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND display_name = 'Asha Rao'`, member.ID); n != 1 {
		t.Error("the sign-in didn't set the asserted display name")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'group.member_added' AND resource_id = $2 AND actor_type = 'saml'`, organization, engineering); n != 1 {
		t.Errorf("%d member_added events by the sign-in, want 1", n)
	}

	sp.signIn(t, idp, conn.ID, answer{nameID: "entra|asha", email: member.Email,
		attributes: map[string][]string{groupsOverage: {"https://graph.microsoft.com/v1.0/users/asha/getMemberObjects"}}})
	if synced() != 1 {
		t.Error("withheld groups took the person out of the group")
	}
	sp.signIn(t, idp, conn.ID, answer{nameID: "entra|asha", email: member.Email})
	if synced() != 0 {
		t.Error("the person is still in the group after the IdP stopped asserting it")
	}
}

// TestAHostedSignInReturnsToTheHostedLogin checks that a sign-in the hosted login started comes
// back to the hosted login's sign-in page with its return address and the one-time code in the
// fragment, and that the code buys the hosted login session once, not a token pair.
func TestAHostedSignInReturnsToTheHostedLogin(t *testing.T) {
	const accounts = "https://accounts.example.test"
	sp := newSPSide(t, func(d *Deps) { d.LoginBaseURL, d.ReturnOrigins = accounts, []string{testPublicBase} })
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	returnTo := testPublicBase + "/oauth/authorize?client_id=portal&state=s1"

	rec := sp.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet,
		"/saml/login/"+conn.ID.String()+"?return_to="+url.QueryEscape(returnTo), nil))
	location, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || location == nil {
		t.Fatalf("login with return_to: %d %s", rec.Code, rec.Body.String())
	}
	ar, err := decodeAuthnRequest(location.Query().Get("SAMLRequest"), http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	answered := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: ar.ID, nameID: "okta|asha", email: member.Email}))
	want := accounts + "/sign-in?" + url.Values{"return_to": {returnTo}}.Encode() + "#saml_code="
	got := answered.Header().Get("Location")
	if answered.Code != http.StatusFound || !strings.HasPrefix(got, want) || len(got) == len(want) {
		t.Fatalf("ACS: %d %s, want the hosted login's sign-in with the code", answered.Code, got)
	}
	code := strings.TrimPrefix(got, want)

	session := dbtest.Do(t, sp.public, http.MethodPost, "/saml/session", map[string]string{"code": code})
	var signedIn struct {
		UserID string `json:"user_id"`
	}
	dbtest.Decode(t, session, &signedIn)
	if session.Code != http.StatusOK || signedIn.UserID != member.ID.String() || !strings.Contains(session.Header().Get("Set-Cookie"), "qe_ls=") {
		t.Fatalf("session: %d %s %q, want the hosted login cookie for the member", session.Code, session.Body.String(), session.Header().Get("Set-Cookie"))
	}
	if again := dbtest.Do(t, sp.public, http.MethodPost, "/saml/session", map[string]string{"code": code}); !strings.Contains(again.Body.String(), CodeLoginCodeUsed) {
		t.Errorf("the code again: %d %s, want %s", again.Code, again.Body.String(), CodeLoginCodeUsed)
	}
}

// TestAFailedHostedSignInReturnsToTheHostedLogin checks that an answer that fails validation, for
// a sign-in this browser began on the hosted login, goes back to the hosted login's sign-in page
// with a generic error and the return address stored when it began, found by the browser's
// binding cookie; and that another browser posting it gets the error itself.
func TestAFailedHostedSignInReturnsToTheHostedLogin(t *testing.T) {
	const accounts = "https://accounts.example.test"
	sp := newSPSide(t, func(d *Deps) { d.LoginBaseURL, d.ReturnOrigins = accounts, []string{testPublicBase} })
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	email := dbtest.Unique("asha") + "@" + dbtest.Domain(t, organization)
	returnTo := testPublicBase + "/oauth/authorize?client_id=portal&state=s2"

	rec := sp.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet,
		"/saml/login/"+conn.ID.String()+"?return_to="+url.QueryEscape(returnTo), nil))
	location, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || location == nil {
		t.Fatalf("login with return_to: %d %s", rec.Code, rec.Body.String())
	}
	ar, err := decodeAuthnRequest(location.Query().Get("SAMLRequest"), http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := idp.respond(t, conn.ID, answer{inResponseTo: ar.ID, email: email, unsigned: true})

	stranger := *sp
	stranger.browser = nil
	if other := stranger.post(t, conn.ID, unsigned); other.Code == http.StatusFound {
		t.Errorf("another browser: redirected to %s, want the error itself", other.Header().Get("Location"))
	}
	answered := sp.post(t, conn.ID, unsigned)
	want := accounts + "/sign-in?" + url.Values{"error": {"sso"}, "return_to": {returnTo}}.Encode()
	if got := answered.Header().Get("Location"); answered.Code != http.StatusFound || got != want {
		t.Fatalf("ACS: %d %s %s, want the hosted login's sign-in with the error", answered.Code, got, answered.Body.String())
	}
}

// TestSAMLToleratesClockSkew checks that an IdP whose clock is two minutes
// off still signs people in, either way, and one five minutes off doesn't.
func TestSAMLToleratesClockSkew(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	now := time.Now().UTC()

	sp.signIn(t, idp, conn.ID, answer{email: member.Email, notBefore: now.Add(2 * time.Minute), notOnOrAfter: now.Add(10 * time.Minute)})
	sp.signIn(t, idp, conn.ID, answer{email: member.Email, notBefore: now.Add(-10 * time.Minute), notOnOrAfter: now.Add(-2 * time.Minute)})

	for _, c := range []struct {
		name string
		a    answer
		want string
	}{
		{"an IdP clock five minutes fast", answer{notBefore: now.Add(5 * time.Minute), notOnOrAfter: now.Add(10 * time.Minute)}, CodeAssertionConditions},
		{"an IdP clock five minutes slow", answer{notBefore: now.Add(-10 * time.Minute), notOnOrAfter: now.Add(-5 * time.Minute)}, errs.CodeSAMLAssertionInvalid},
	} {
		a := c.a
		a.inResponseTo, a.email = sp.begin(t, conn.ID), member.Email
		if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, a)); rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s, want %s", c.name, rec.Code, rec.Body.String(), c.want)
		}
	}
}
