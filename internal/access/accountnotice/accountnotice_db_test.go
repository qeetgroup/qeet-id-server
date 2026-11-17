//go:build integration

package accountnotice

import (
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestTellEmailsTheAccountHolder checks that a notice goes to the account's
// address with its organization, says what to do if it wasn't them, and isn't
// sent for a deleted account or without a sender.
func TestTellEmailsTheAccountHolder(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	organization := dbtest.Organization(t)
	a, gone := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	mail := &dbtest.Mailbox{}

	Tell(ctx, pool, mail, a.ID, "Your password was changed", "A new password was set.")
	m := mail.Last(t)
	if m.To != a.Email || m.Channel != "email" || m.OrganizationID != organization.String() || m.Subject != "Your password was changed" ||
		!strings.Contains(m.Body, wasntYou) || !strings.Contains(m.HTML, "reset your password") {
		t.Errorf("notice %+v; want it to the person, in their organisation, saying what to do", m)
	}
	Tell(ctx, pool, mail, gone.ID, "Your password was changed", "A new password was set.")
	Tell(ctx, pool, nil, a.ID, "Your password was changed", "A new password was set.")
	if n := mail.Len(); n != 1 {
		t.Errorf("%d notices sent, want only the first: none for a deleted account or without a sender", n)
	}
}
