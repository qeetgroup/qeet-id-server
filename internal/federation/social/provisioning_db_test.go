//go:build integration

package social

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/identity/invite"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestOIDCSocialProviderDoesNotVerifyAnAddressItsOrganizationDoesNotManage
// checks that a provider whose endpoints the organization chooses vouches only
// for addresses on the organization's verified domains. Elsewhere a new
// account's address stays unproved and an existing account isn't adopted,
// while GitHub's fixed endpoints still vouch for any address.
func TestOIDCSocialProviderDoesNotVerifyAnAddressItsOrganizationDoesNotManage(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	organization := openOrganization(t)
	domain := dbtest.Domain(t, organization)
	signIn := func(provider string, person userInfo) (uuid.UUID, error) {
		return svc.findOrCreateUser(ctx, organization, provider, person)
	}

	outsider := claims(dbtest.Unique("outsider") + "@example.test")
	id, err := signIn("okta", outsider)
	if err != nil || proved(t, id) {
		t.Errorf("a new account on a domain the organization doesn't manage: %v, address proved %v; want it created unproved", err, proved(t, id))
	}
	if again, err := signIn("okta", outsider); err != nil || again != id || proved(t, id) {
		t.Errorf("the same person signing in again = %s, %v; want the account %s, still unproved", again, err, id)
	}
	if id, err := signIn("okta", claims(dbtest.Unique("insider")+"@"+domain)); err != nil || !proved(t, id) {
		t.Errorf("a new account on the organization's own domain: %v; want it created proved", err)
	}
	if id, err := signIn("github", claims(dbtest.Unique("octo")+"@example.test")); err != nil || !proved(t, id) {
		t.Errorf("a new account GitHub verified: %v; want it created proved", err)
	}

	elsewhere := dbtest.User(t, organization, organization)
	if got, err := signIn("okta", verified(t, elsewhere)); !errors.Is(err, ErrEmailUnverified) {
		t.Errorf("an account on a domain the organization doesn't manage = %s, %v; want %v", got, err, ErrEmailUnverified)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, elsewhere.ID); n != 0 {
		t.Errorf("%d identities linked to an account the provider can't vouch for, want none", n)
	}
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	if got, err := signIn("okta", verified(t, member)); err != nil || got != member.ID {
		t.Errorf("an account on the organization's own domain = %s, %v; want it adopted", got, err)
	}
}

// TestInboxClosedToAnAddressOnlyAProviderAsserted checks that an organization
// can't reach another's invitation by pointing a provider of its own at a
// server that claims the invited address: the account it creates is unproved,
// so the invitations inbox stays closed to it.
func TestInboxClosedToAnAddressOnlyAProviderAsserted(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSocialFixture(t)

	inviting := dbtest.Organization(t)
	inviter := dbtest.User(t, inviting, inviting)
	invitee := dbtest.Unique("new.hire") + "@example.test"
	role := dbtest.Role(t, inviting, "user.read")
	policies := registrationPolicies(t)
	invites, err := invite.NewService(pool, invite.Deps{
		Sender: &dbtest.Mailbox{}, BaseAppURL: "https://console.example.test", Rules: policies,
		Methods: policies, Limits: noSeatCap{}, Grants: rbac.NewRepository(pool).CheckGrantRole,
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, _, err := invites.Create(ctx, invite.CreateInput{OrganizationID: inviting, Email: invitee, RoleID: &role}, audit.Actor{UserID: &inviter.ID, Type: "user"})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	organization := openOrganization(t)
	addProvider(t, f, organization, "corp")
	if _, q := redirectQuery(t, f.signIn(t, "corp", "/social/corp/start?organization_id="+organization.String(), claims(invitee))); q.Get("code") == "" {
		t.Fatalf("sign-up through the organization's provider: %v; want a one-time code", q)
	}
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM account.users WHERE email = $1`, invitee).Scan(&id); err != nil {
		t.Fatalf("the account the sign-up created: %v", err)
	}

	if list, err := invites.ListForUser(ctx, id); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
		t.Errorf("the inbox of an address only the provider asserted = %+v, %v; want %v", list, err, errs.ErrInviteEmailNotVerified)
	}
	if _, err := invites.AcceptAuthenticatedByID(ctx, id, inv.ID, audit.Actor{}); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
		t.Errorf("accepting from the inbox: %v; want %v", err, errs.ErrInviteEmailNotVerified)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, id, inviting); n != 0 {
		t.Errorf("the account holds %d roles in the inviting organization, want none", n)
	}
}

// TestSocialSignUpRefusedOnADomainAnotherOrganizationManages checks that no
// provider of an organization, whatever its kind, creates an account on a
// domain another organization verified, or below it, while the organization
// that manages the domain still can. The browser is told no more than that
// the sign-in failed.
func TestSocialSignUpRefusedOnADomainAnotherOrganizationManages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	organization, manager := openOrganization(t), openOrganization(t)
	domain := dbtest.Domain(t, manager)

	f := newSocialFixture(t)
	addProvider(t, f, organization, "corp")
	taken := dbtest.Unique("x") + "@" + domain
	target, q := redirectQuery(t, f.signIn(t, "corp", "/social/corp/start?organization_id="+organization.String(), claims(taken)))
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, taken); target != "https://login.example.test/sign-in" || q.Get("error") != "social" || q.Get("code") != "" || n != 0 {
		t.Errorf("sign-up through the routes went to %s %v, %d accounts; want the hosted login with error=social and no account", target, q, n)
	}

	for _, provider := range []string{"okta", "github"} {
		for _, host := range []string{domain, "eu." + domain} {
			email := dbtest.Unique("x") + "@" + host
			_, err := svc.findOrCreateUser(ctx, organization, provider, claims(email))
			if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email); !errors.Is(err, errs.ErrUserDomainManaged) || n != 0 {
				t.Errorf("%s sign-up at %s: %v, %d accounts; want %v and no account", provider, host, err, n, errs.ErrUserDomainManaged)
			}
		}
	}
	email := dbtest.Unique("own") + "@" + domain
	if id, err := svc.findOrCreateUser(ctx, manager, "okta", claims(email)); err != nil || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2`, id, manager) != 1 {
		t.Errorf("sign-up through the managing organization's own provider: %v; want an account in it", err)
	}
}

// TestSocialSignUpRefusedOnACapturedDomain checks that once an organization
// requires single sign-on on its domain, with an active connection, its social
// providers create no account there: new people arrive through the connection.
func TestSocialSignUpRefusedOnACapturedDomain(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	organization := openOrganization(t)
	domain := dbtest.Domain(t, organization)
	signUp := func() (string, error) {
		email := dbtest.Unique("x") + "@" + domain
		_, err := svc.findOrCreateUser(ctx, organization, "github", claims(email))
		return email, err
	}

	if email, err := signUp(); err != nil || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email) != 1 {
		t.Errorf("sign-up on the organization's domain before it requires single sign-on: %v; want an account", err)
	}
	requireSSO(t, organization)
	if email, err := signUp(); !errors.Is(err, errs.ErrAuthSSORequired) || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email) != 0 {
		t.Errorf("sign-up on a domain that requires single sign-on: %v; want %v and no account", err, errs.ErrAuthSSORequired)
	}
}

// TestSocialDoesNotAdoptAnAdministrator checks that no provider of an
// organization, whatever its kind, takes over by its address an account that
// owns or administers the organization, directly or through a group, while a
// member holding only read permissions is still adopted. Through the routes
// the browser is told no more than that the sign-in failed.
func TestSocialDoesNotAdoptAnAdministrator(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := provisioningService(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	account := func(roles ...uuid.UUID) dbtest.Account {
		a := dbtest.UserAt(t, dbtest.Unique("user")+"@"+domain, organization, organization)
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
	owner := account(ownerRole)
	linked := func(a dbtest.Account) int {
		return dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, a.ID)
	}

	for name, a := range map[string]dbtest.Account{
		"an owner":                               owner,
		"an account holding connection.write":    account(dbtest.Role(t, organization, "user.read", "connection.write")),
		"a member of a group holding role.write": grouped,
	} {
		for _, provider := range []string{"okta", "github"} {
			if got, err := svc.findOrCreateUser(ctx, organization, provider, verified(t, a)); !errors.Is(err, ErrAccountAdministers) {
				t.Errorf("%s through %s = %s, %v; want %v", name, provider, got, err, ErrAccountAdministers)
			}
		}
		if n := linked(a); n != 0 {
			t.Errorf("%s was linked to %d providers, want none", name, n)
		}
	}

	reader := account(dbtest.Role(t, organization, "user.read", "audit.read"))
	if got, err := svc.findOrCreateUser(ctx, organization, "okta", verified(t, reader)); err != nil || got != reader.ID {
		t.Errorf("an account holding only read permissions = %s, %v; want it adopted", got, err)
	}

	f := newSocialFixture(t)
	addProvider(t, f, organization, "corp")
	target, q := redirectQuery(t, f.signIn(t, "corp", "/social/corp/start?organization_id="+organization.String(), verified(t, owner)))
	if target != "https://login.example.test/sign-in" || q.Get("error") != "social" || q.Get("code") != "" || linked(owner) != 0 {
		t.Errorf("the owner's address through the routes went to %s %v; want the hosted login with error=social and no link", target, q)
	}
}

// TestSocialSignInRefusedOnACapturedDomain checks that once an organization
// requires single sign-on on its domain, none of its social providers signs a
// member in there, whether their identity is linked already or would be
// adopted by address, and nothing new is linked; a break-glass member still
// signs in.
func TestSocialSignInRefusedOnACapturedDomain(t *testing.T) {
	f := newSocialFixture(t, capturing(t))
	organization := dbtest.Organization(t)
	domain := dbtest.Domain(t, organization)
	addProvider(t, f, organization, "corp")
	start := "/social/corp/start?organization_id=" + organization.String()
	member := func() (dbtest.Account, userInfo) {
		a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
		return a, verified(t, a)
	}
	signIn := func(person userInfo) url.Values {
		_, q := redirectQuery(t, f.signIn(t, "corp", start, person))
		return q
	}
	_, linkedAs := member()
	if q := signIn(linkedAs); q.Get("code") == "" {
		t.Fatalf("sign-in before the organization requires single sign-on: %v; want a code", q)
	}
	exempt, exemptAs := member()
	breakGlass(t, organization, exempt)
	adopted, adoptedAs := member()

	requireSSO(t, organization)
	if q := signIn(linkedAs); q.Get("code") != "" || q.Get("error") != "social" {
		t.Errorf("a linked member's sign-in on a captured domain: %v; want error=social and no code", q)
	}
	if q := signIn(adoptedAs); q.Get("code") != "" {
		t.Errorf("adopting a member on a captured domain: %v; want no code", q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, adopted.ID); n != 0 {
		t.Errorf("%d identities linked to a member on a captured domain, want none", n)
	}
	if q := signIn(exemptAs); q.Get("code") == "" {
		t.Errorf("a break-glass member's sign-in: %v; want a code", q)
	}
}

// TestSocialRecordsARefusedAdoption checks that an address the provider may
// not adopt an account by is recorded as a failed sign-in, with the reason, as
// every protocol records one.
func TestSocialRecordsARefusedAdoption(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	organization := openOrganization(t)
	admin := dbtest.UserAt(t, dbtest.Unique("root")+"@example.test", organization, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "user.write"))
	if _, err := svc.findOrCreateUser(ctx, organization, "github", verified(t, admin)); !errors.Is(err, ErrAccountAdministers) {
		t.Fatalf("an administrator's address: %v, want %v", err, ErrAccountAdministers)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_failed'
		AND metadata->>'method' = 'social' AND metadata->>'reason' = $2 AND metadata->>'provider' = 'github' AND actor_user_id = $3`,
		organization, CodeAccountAdministers, admin.ID); n != 1 {
		t.Errorf("%d failed sign-ins recorded for the refused adoption, want 1", n)
	}
}

// TestSocialRelinkRefreshesTheLinksAddress checks that a linked identity's
// next sign-in records the address the provider now gives on its link, as
// OpenID Connect single sign-on does, and that a new account's address is
// kept lower-cased, as every other sign-in keeps it.
func TestSocialRelinkRefreshesTheLinksAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	organization := openOrganization(t)
	subject := "gh-" + uuid.NewString()
	first := dbtest.Unique("Asha") + "@Example.TEST"
	id, err := svc.findOrCreateUser(ctx, organization, "github", userInfo{Subject: subject, Email: first, EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email = $2`, id, strings.ToLower(first)); n != 1 {
		t.Errorf("the new account's address isn't kept lower-cased")
	}
	moved := dbtest.Unique("asha.rao") + "@example.test"
	again, err := svc.findOrCreateUser(ctx, organization, "github", userInfo{Subject: subject, Email: moved, EmailVerified: true})
	if err != nil || again != id {
		t.Fatalf("the linked identity's next sign-in: %s, %v; want %s", again, err, id)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND provider = 'github' AND subject = $2 AND email = $3`, id, subject, moved); n != 1 {
		t.Errorf("the link doesn't hold the address the provider now gives")
	}
}

// TestSocialSignInAdoptsOnlyAnAccountInTheOrganization checks that a verified
// address adopts an existing account only in its home organization: an organization where
// it merely holds a role, like any other, is refused, so that organization's provider
// can't sign a guest in and switch into the guest's home.
func TestSocialSignInAdoptsOnlyAnAccountInTheOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), newAuthService(t, nil))
	home, joined, other := dbtest.Organization(t), dbtest.Organization(t), dbtest.Organization(t)
	account := dbtest.User(t, home, joined)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, account.ID); err != nil {
		t.Fatal(err)
	}
	// GitHub, whose endpoints are fixed, vouches for an address in any organization.
	signIn := func(organization uuid.UUID) (uuid.UUID, error) {
		return svc.findOrCreateUser(ctx, organization, "github", userInfo{Subject: uuid.NewString(), Email: account.Email, EmailVerified: true})
	}

	if got, err := signIn(home); err != nil || got != account.ID {
		t.Errorf("sign-in to the home organization = %s, %v; want the account %s", got, err, account.ID)
	}
	for name, organization := range map[string]uuid.UUID{"joined": joined, "another": other} {
		if got, err := signIn(organization); !errors.Is(err, ErrAccountNotInOrganization) {
			t.Errorf("sign-in to the %s organization = %s, %v; want %v", name, got, err, ErrAccountNotInOrganization)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND organization_id <> $2`, account.ID, home); n != 0 {
		t.Errorf("another organization's sign-in linked %d identities", n)
	}
}

// TestSocialSignUpWithOneConnection checks, with only one connection free,
// that a social sign-in with an address nobody holds creates an account where
// the organization allows self-registration, and is refused where it doesn't.
func TestSocialSignUpWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool, newAuthService(t, registrationPolicies(t)))
	open, closed := dbtest.Organization(t), dbtest.Organization(t)
	if _, err := pool.Exec(ctx, `INSERT INTO organization.auth_policy (organization_id, self_registration_enabled) VALUES ($1, TRUE)`, open); err != nil {
		t.Fatalf("policy: %v", err)
	}
	signUp := func(organization uuid.UUID) (string, uuid.UUID, error) {
		email := dbtest.Unique("social") + "@example.test"
		id, err := svc.findOrCreateUser(ctx, organization, "google", userInfo{Subject: uuid.NewString(), Email: email, EmailVerified: true})
		return email, id, err
	}

	dbtest.LeaveOneConnection(t)
	if email, id, err := signUp(open); err != nil || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email = $2 AND organization_id = $3`, id, email, open) != 1 {
		t.Errorf("sign-up where self-registration is on: %s, %v; want an account in the organization", id, err)
	}
	if email, _, err := signUp(closed); !errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) || dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email) != 0 {
		t.Errorf("sign-up where self-registration is off: %v; want %v and no account", err, errs.ErrAuthSelfRegistrationDisabled)
	}
}

// TestSocialSignInAdoptsADirectoryProvisionedAccount checks that an account
// the organization's directory provisioned, its address never proved, is
// adopted by a verified sign-in and marked verified, while an unproved account
// registered any other way is still refused.
func TestSocialSignInAdoptsADirectoryProvisionedAccount(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool, newAuthService(t, nil))
	organization := dbtest.Organization(t)
	provisioned, registered := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET provisioned_via = 'scim' WHERE id = $1`, provisioned.ID); err != nil {
		t.Fatal(err)
	}
	signIn := func(email string) (uuid.UUID, error) {
		return svc.findOrCreateUser(ctx, organization, "github", userInfo{Subject: uuid.NewString(), Email: email, EmailVerified: true})
	}
	if got, err := signIn(provisioned.Email); err != nil || got != provisioned.ID {
		t.Errorf("a directory-provisioned account: %s, %v; want it adopted", got, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND email_verified_at IS NOT NULL`, provisioned.ID); n != 1 {
		t.Error("the adopted account's address was not marked verified")
	}
	if _, err := signIn(registered.Email); !errors.Is(err, ErrAccountUnverified) {
		t.Errorf("an unproved account registered otherwise: %v, want %v", err, ErrAccountUnverified)
	}
}

// TestSocialSignInIgnoresConnectionLinks checks that a social provider named
// like a single sign-on kind (saml, ldap, oidc) doesn't find a person linked
// through one of the organization's connections by that subject, so whoever
// controls such a provider can't sign in as them.
func TestSocialSignInIgnoresConnectionLinks(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), newAuthService(t, nil))
	organization := dbtest.Organization(t)
	linked := dbtest.User(t, organization, organization)
	for _, provider := range []string{"saml", "ldap", "oidc"} {
		subject := provider + "-subject-" + uuid.NewString()
		if _, err := dbtest.Pool(t).Exec(ctx, `
			INSERT INTO account.external_identities (user_id, organization_id, provider, subject, email, connection_id)
			VALUES ($1, $2, $3, $4, $5, $6)`, linked.ID, organization, provider, subject, linked.Email, uuid.New()); err != nil {
			t.Fatal(err)
		}
		got, err := svc.findOrCreateUser(ctx, organization, provider, userInfo{Subject: subject})
		if got == linked.ID || !errors.Is(err, ErrEmailMissing) {
			t.Errorf("a social %q sign-in with a connection's subject = %s, %v; want no link found", provider, got, err)
		}
	}
}

// noSeatCap puts no cap on seats.
type noSeatCap struct{}

func (noSeatCap) Limit(context.Context, uuid.UUID, string) (int, error) { return -1, nil }
