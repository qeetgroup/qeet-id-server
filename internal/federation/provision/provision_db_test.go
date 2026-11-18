//go:build integration

package provision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

var (
	errNotHome        = errors.New("not home")
	errMissing        = errors.New("email missing")
	errUnverified     = errors.New("account unverified")
	errAdministers    = errors.New("administers")
	errDomain         = errors.New("domain unverified")
	errProviderSaysNo = errors.New("provider says unverified")
	errJIT            = errors.New("jit not allowed")
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// maxDisplayName is the longest display name an account takes.
const maxDisplayName = 200

// testFlow is a single sign-on flow through a connection.
func testFlow(t *testing.T) *Flow {
	t.Helper()
	return &Flow{Pool: dbtest.Pool(t), Method: "saml", Recorder: unrecorded{},
		Errors: Errors{NotHome: errNotHome, EmailMissing: errMissing, AccountUnverified: errUnverified, AccountAdministers: errAdministers,
			DomainUnverified: errDomain, EmailUnverified: errProviderSaysNo, JITNotAllowed: errJIT}}
}

// TestResolveFollowsTheSingleSignOnRules checks the flow a connection signs
// people in by: a new account only on the organization's own domain with
// just-in-time provisioning on, its display name only within an account's
// limit; no account on an address the provider says it hasn't verified; an
// adoption only of a verified home account that doesn't administer the
// organization; and the subject linked, then signing in the same account.
func TestResolveFollowsTheSingleSignOnRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := testFlow(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	src := Source{OrganizationID: organization, Provider: "saml", ConnectionID: uuid.New()}
	no := false

	for name, c := range map[string]struct {
		p    Person
		want error
	}{
		"an address off the organization's domains":      {Person{Subject: "s-1", Email: dbtest.Unique("a") + "@example.test"}, errDomain},
		"an address the provider says it hasn't checked": {Person{Subject: "s-2", Email: dbtest.Unique("a") + "@" + domain, EmailVerified: &no}, errProviderSaysNo},
		"no address": {Person{Subject: "s-3"}, errMissing},
	} {
		if _, err := f.Resolve(ctx, src, c.p, audit.Actor{}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	long, fits := strings.Repeat("n", maxDisplayName+1), strings.Repeat("n", maxDisplayName)
	newcomer := dbtest.Unique("Ravi") + "@" + strings.ToUpper(domain)
	id, err := f.Resolve(ctx, src, Person{Subject: "s-new", Email: newcomer, Name: long}, audit.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2 AND email = $3
		AND email_verified_at IS NOT NULL AND display_name IS NULL`, id, organization, strings.ToLower(newcomer)); n != 1 {
		t.Error("the newcomer wasn't created verified, lower-cased, without a display name too long for an account")
	}
	if again, err := f.Resolve(ctx, src, Person{Subject: "s-new", Email: dbtest.Unique("x") + "@example.test"}, audit.Actor{}); err != nil || again != id {
		t.Errorf("the linked subject: %s, %v; want %s", again, err, id)
	}
	named, err := f.Resolve(ctx, src, Person{Subject: "s-named", Email: dbtest.Unique("asha") + "@" + domain, Name: fits}, audit.Actor{})
	if err != nil || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND display_name = $2`, named, fits) != 1 {
		t.Errorf("a display name of an account's length: %v", err)
	}

	unverified := dbtest.UserAt(t, dbtest.Unique("u")+"@"+domain, organization, organization)
	admin := dbtest.UserAt(t, dbtest.Unique("root")+"@"+domain, organization, organization)
	guest := dbtest.UserAt(t, dbtest.Unique("guest")+"@"+domain, dbtest.Organization(t), organization)
	for _, a := range []dbtest.Account{admin, guest} {
		if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "user.write"))
	for name, c := range map[string]struct {
		a    dbtest.Account
		want error
	}{
		"an account that never proved its address": {unverified, errUnverified},
		"an administrator":                         {admin, errAdministers},
		"a guest whose home is elsewhere":          {guest, errNotHome},
	} {
		if _, err := f.Resolve(ctx, src, Person{Subject: "s-" + c.a.ID.String(), Email: c.a.Email}, audit.Actor{}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, c.a.ID); n != 0 {
			t.Errorf("%s was linked", name)
		}
	}

	if _, err := pool.Exec(ctx, `UPDATE organization.domains SET jit_enabled = FALSE WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Resolve(ctx, src, Person{Subject: "s-late", Email: dbtest.Unique("late") + "@" + domain}, audit.Actor{}); !errors.Is(err, errJIT) {
		t.Errorf("a newcomer once just-in-time provisioning is off: %v, want %v", err, errJIT)
	}
}

// TestResolveFailsClosed checks that a flow whose protocol names no error for
// a refusal refuses all the same, creating nothing.
func TestResolveFailsClosed(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	src := Source{OrganizationID: organization, Provider: "saml", ConnectionID: uuid.New()}
	bare := &Flow{Pool: dbtest.Pool(t), Recorder: unrecorded{}}
	email := dbtest.Unique("a") + "@example.test"
	if id, err := bare.Resolve(ctx, src, Person{Subject: "s-1", Email: email}, audit.Actor{}); err == nil {
		t.Errorf("an address off the organization's domains, with no error named: signed in %s", id)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE lower(email) = lower($1)`, email); n != 0 {
		t.Error("the refused sign-in created an account")
	}
}

// unrecorded records no refused sign-in.
type unrecorded struct{}

func (unrecorded) RecordSignInFailure(context.Context, auth.SignInFailure) {}
