//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
		{"an IdP clock five minutes fast", answer{notBefore: now.Add(5 * time.Minute), notOnOrAfter: now.Add(10 * time.Minute)}, errs.CodeSAMLAssertionConditions},
		{"an IdP clock five minutes slow", answer{notBefore: now.Add(-10 * time.Minute), notOnOrAfter: now.Add(-5 * time.Minute)}, errs.CodeSAMLAssertionInvalid},
	} {
		a := c.a
		a.inResponseTo, a.email = sp.begin(t, conn.ID), member.Email
		if rec := sp.post(t, conn.ID, idp.respond(t, conn.ID, a)); rec.Code == http.StatusFound || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s, want %s", c.name, rec.Code, rec.Body.String(), c.want)
		}
	}
}
