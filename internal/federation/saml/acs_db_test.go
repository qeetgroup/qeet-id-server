//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestACSAnswers pins what the ACS leaves behind for each kind of answer: a
// sign-in's one-time code, stored for the person and the connection, and the
// connection's last sign-in; a refused answer, no code and the request kept
// or spent as it was; and an answer from another browser, its request spent
// and no code.
func TestACSAnswers(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	sp, idp := newSPSide(t), newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	codesOf := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE connection_id = $1`, conn.ID)
	}
	open := func(requestID string) int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.saml_authn_requests WHERE request_id = $1`, requestID)
	}

	requestID := sp.begin(t, conn.ID)
	if rec := sp.post(t, conn.ID, ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), CodeResponseMissing) {
		t.Errorf("no SAMLResponse: %d %s", rec.Code, rec.Body.String())
	}
	if codesOf() != 0 || open(requestID) != 1 {
		t.Errorf("after a missing answer: %d codes, %d open requests; want none and the request kept", codesOf(), open(requestID))
	}
	code := loginCode(t, sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: requestID, nameID: "okta|asha", email: member.Email})))
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE code_hash = $1 AND kind = 'saml' AND user_id = $2 AND organization_id = $3 AND connection_id = $4`,
		codes.Hash(code), member.ID, organization, conn.ID); n != 1 {
		t.Errorf("%d login codes for the sign-in, want 1 of kind saml for the member and the connection", n)
	}
	if open(requestID) != 0 {
		t.Error("the answered request is still open")
	}
	var signedIn bool
	if err := pool.QueryRow(ctx, `SELECT last_login_at IS NOT NULL FROM organization.saml_connections WHERE id = $1`, conn.ID).Scan(&signedIn); err != nil || !signedIn {
		t.Errorf("the connection's last sign-in: %t, %v", signedIn, err)
	}

	elsewhere := newSPSide(t)
	requestID = elsewhere.begin(t, conn.ID)
	if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: requestID, nameID: "okta|asha", email: member.Email})); !strings.Contains(rec.Body.String(), CodeOtherBrowser) {
		t.Errorf("an answer to another browser's request: %d %s, want %s", rec.Code, rec.Body.String(), CodeOtherBrowser)
	}
	if codesOf() != 1 || open(requestID) != 0 {
		t.Errorf("after another browser's answer: %d codes, %d open requests; want only the first code and the request spent", codesOf(), open(requestID))
	}
}
