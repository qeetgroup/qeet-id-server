//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestSAMLCodeOfAConnectionTurnedOffDoesNotExchange checks that a login code
// issued just before its connection was disabled, put back to draft or deleted
// signs nobody in, at /saml/exchange or at the hosted /saml/session.
func TestSAMLCodeOfAConnectionTurnedOffDoesNotExchange(t *testing.T) {
	ctx := dbtest.Context(t)
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	member := dbtest.UserAt(t, dbtest.Unique("user")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	code := func(conn Connection) string {
		t.Helper()
		return loginCode(t, sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: member.Email})))
	}
	for _, tc := range []struct{ change, want string }{
		{`UPDATE organization.saml_connections SET status = 'disabled' WHERE id = $1`, CodeConnectionDisabled},
		{`UPDATE organization.saml_connections SET status = 'draft' WHERE id = $1`, CodeConnectionDraft},
		{`DELETE FROM organization.saml_connections WHERE id = $1`, CodeLoginCodeInvalid},
	} {
		conn := sp.connect(t, organization, idp)
		exchange, session := code(conn), code(conn)
		if _, err := dbtest.Pool(t).Exec(ctx, tc.change, conn.ID); err != nil {
			t.Fatal(err)
		}
		if rec := sp.exchange(t, exchange); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s, then exchange its code: %d %s, want %s", tc.change, rec.Code, rec.Body.String(), tc.want)
		}
		if rec := dbtest.Do(t, sp.public, http.MethodPost, "/saml/session", map[string]string{"code": session}); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s, then trade its code for a hosted session: %d %s, want %s", tc.change, rec.Code, rec.Body.String(), tc.want)
		}
	}
}
