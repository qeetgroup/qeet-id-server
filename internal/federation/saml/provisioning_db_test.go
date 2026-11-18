//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// refusals counts the failed sign-ins through connection recorded in
// organization for reason.
func refusals(t *testing.T, organization, connection, reason string) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_failed'
		AND metadata->>'method' = 'saml' AND metadata->>'reason' = $2 AND metadata->>'connection_id' = $3`, organization, reason, connection)
}

// TestSAMLRecordsARefusedAdoption checks that an assertion the connection may
// not sign its account in by is recorded as a failed sign-in, with the reason,
// as every protocol records one, naming only the organization's own account.
func TestSAMLRecordsARefusedAdoption(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	admin := dbtest.UserAt(t, dbtest.Unique("root")+"@"+dbtest.Domain(t, organization), organization)
	verify(t, admin.ID)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "connection.write"))
	outsider := dbtest.UserAt(t, dbtest.Unique("out")+"@example.test", dbtest.Organization(t))

	for _, c := range []struct{ email, reason string }{
		{admin.Email, CodeAccountAdministers},
		{outsider.Email, CodeEmailDomainUnverified},
	} {
		if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: c.email})); rec.Code == http.StatusFound {
			t.Fatalf("%s: %d, want refused", c.reason, rec.Code)
		}
		if n := refusals(t, organization.String(), conn.ID.String(), c.reason); n != 1 {
			t.Errorf("%d failed sign-ins recorded for %s, want 1", n, c.reason)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_failed' AND actor_user_id = $1`, admin.ID); n != 1 {
		t.Errorf("%d failed sign-ins name the administrator the assertion named, want 1", n)
	}
	// Another organization's account stays out of this organization's trail.
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND actor_user_id = $2`, organization, outsider.ID); n != 0 {
		t.Errorf("%d records name another organization's account", n)
	}
}

// TestSAMLRelinkRefreshesTheLinksAddress checks that a linked subject's next
// sign-in records the address it now asserts on its link, as OpenID Connect
// sign-in does.
func TestSAMLRelinkRefreshesTheLinksAddress(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	domain := dbtest.Domain(t, organization)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	verify(t, member.ID)
	sp.signIn(t, idp, conn.ID, answer{nameID: "okta|asha", email: member.Email})
	moved := dbtest.Unique("asha.rao") + "@" + domain
	if got := sp.signIn(t, idp, conn.ID, answer{nameID: "okta|asha", email: moved}); got.UserID != member.ID {
		t.Fatalf("the linked subject signed in %s, want %s", got.UserID, member.ID)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND subject = 'okta|asha' AND email = $2`, member.ID, moved); n != 1 {
		t.Errorf("the link doesn't hold the address the IdP now asserts")
	}
}

// TestSAMLGivesASuspendedAccountNoCode checks that the ACS hands a suspended
// account no login code, as OpenID Connect and social sign-in don't.
func TestSAMLGivesASuspendedAccountNoCode(t *testing.T) {
	sp := newSPSide(t)
	idp := newUpstreamIdP(t)
	organization := dbtest.Organization(t)
	conn := sp.connect(t, organization, idp)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	sp.signIn(t, idp, conn.ID, answer{email: member.Email})
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET status = 'suspended' WHERE id = $1`, member.ID); err != nil {
		t.Fatal(err)
	}
	before := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1`, member.ID)
	rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, answer{inResponseTo: sp.begin(t, conn.ID), email: member.Email}))
	if rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), errs.CodeAuthAccountInactive) {
		t.Errorf("a suspended account's assertion: %d %s %s, want %s", rec.Code, rec.Header().Get("Location"), rec.Body.String(), errs.CodeAuthAccountInactive)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1`, member.ID); n != before {
		t.Errorf("a suspended account was issued a login code")
	}
}
