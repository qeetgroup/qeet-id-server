//go:build integration

package social

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// openTenant creates a tenant that lets people register themselves.
func openTenant(t *testing.T) uuid.UUID {
	t.Helper()
	tenant := dbtest.Tenant(t)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO tenant.auth_policy (tenant_id, self_registration_enabled) VALUES ($1, TRUE)`, tenant); err != nil {
		t.Fatalf("policy: %v", err)
	}
	return tenant
}

// provisioningService returns the service reading each tenant's registration
// policy and domain capture, as bootstrap wires it.
func provisioningService(t *testing.T) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetRegistrationPolicy(authpolicy.NewService(pool))
	capture := domainverify.NewService(pool)
	capture.SetMemberPermissions(identitylink.MemberPermissions())
	svc := NewService(pool, authSvc, "https://api.id.qeet.in")
	svc.SetDomainCapture(capture)
	return svc
}

// addProvider gives tenant the fixture's identity provider under name, an
// OpenID Connect provider found by its discovery URL, through the admin route.
func addProvider(t *testing.T, f *socialFixture, tenant uuid.UUID, name string) {
	t.Helper()
	admin := dbtest.User(t, tenant, tenant)
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, tenant), f.mount), http.MethodPost, "/social/providers", map[string]string{
		"provider": name, "client_id": "qeet", "client_secret": "idp-client-secret",
		"discovery_url": f.idp.URL + "/.well-known/openid-configuration",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("add provider %s: %d %s", name, rec.Code, rec.Body.String())
	}
}

// requireSSO makes tenant require single sign-on on its verified domains,
// through an active SAML connection.
func requireSSO(t *testing.T, tenant uuid.UUID) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	if _, err := pool.Exec(ctx, `UPDATE tenant.domains SET sso_enabled = TRUE WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant.saml_connections (tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, status)
		VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert', 'active')`, tenant); err != nil {
		t.Fatal(err)
	}
}

// capturing gives f's service the domain capture bootstrap wires.
func capturing(t *testing.T, f *socialFixture) {
	t.Helper()
	capture := domainverify.NewService(dbtest.Pool(t))
	capture.SetMemberPermissions(identitylink.MemberPermissions())
	f.svc.SetDomainCapture(capture)
}

// breakGlass names a as a member of tenant who keeps their own sign-in methods.
func breakGlass(t *testing.T, tenant uuid.UUID, a dbtest.Account) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO tenant.break_glass_members (tenant_id, user_id) VALUES ($1, $2)`, tenant, a.ID); err != nil {
		t.Fatal(err)
	}
}

// claims is what a provider asserts for a new subject at email, as verified.
func claims(email string) userInfo {
	return userInfo{Subject: uuid.NewString(), Email: email, EmailVerified: true}
}

// proved reports whether the account's address is marked verified.
func proved(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND email_verified_at IS NOT NULL`, id) == 1
}

// TestOIDCSocialProviderDoesNotVerifyAnAddressItsOrganisationDoesNotManage
// checks that a provider whose endpoints the organisation chooses vouches only
// for addresses on the organisation's verified domains. Elsewhere a new
// account's address stays unproved and an existing account isn't adopted,
// while GitHub's fixed endpoints still vouch for any address.
func TestOIDCSocialProviderDoesNotVerifyAnAddressItsOrganisationDoesNotManage(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	tenant := openTenant(t)
	domain := dbtest.Domain(t, tenant)
	signIn := func(provider string, person userInfo) (uuid.UUID, error) {
		return svc.findOrCreateUser(ctx, tenant, provider, person)
	}

	outsider := claims(dbtest.Unique("outsider") + "@example.test")
	id, err := signIn("okta", outsider)
	if err != nil || proved(t, id) {
		t.Errorf("a new account on a domain the organisation doesn't manage: %v, address proved %v; want it created unproved", err, proved(t, id))
	}
	if again, err := signIn("okta", outsider); err != nil || again != id || proved(t, id) {
		t.Errorf("the same person signing in again = %s, %v; want the account %s, still unproved", again, err, id)
	}
	if id, err := signIn("okta", claims(dbtest.Unique("insider")+"@"+domain)); err != nil || !proved(t, id) {
		t.Errorf("a new account on the organisation's own domain: %v; want it created proved", err)
	}
	if id, err := signIn("github", claims(dbtest.Unique("octo")+"@example.test")); err != nil || !proved(t, id) {
		t.Errorf("a new account GitHub verified: %v; want it created proved", err)
	}

	elsewhere := dbtest.User(t, tenant, tenant)
	if got, err := signIn("okta", verified(t, elsewhere)); !errors.Is(err, errs.ErrSocialEmailUnverified) {
		t.Errorf("an account on a domain the organisation doesn't manage = %s, %v; want %v", got, err, errs.ErrSocialEmailUnverified)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, elsewhere.ID); n != 0 {
		t.Errorf("%d identities linked to an account the provider can't vouch for, want none", n)
	}
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, tenant, tenant)
	if got, err := signIn("okta", verified(t, member)); err != nil || got != member.ID {
		t.Errorf("an account on the organisation's own domain = %s, %v; want it adopted", got, err)
	}
}

// TestInboxClosedToAnAddressOnlyAProviderAsserted checks that an organisation
// can't reach another's invitation by pointing a provider of its own at a
// server that claims the invited address: the account it creates is unproved,
// so the invitations inbox stays closed to it.
func TestInboxClosedToAnAddressOnlyAProviderAsserted(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	f := newSocialFixture(t)

	inviting := dbtest.Tenant(t)
	inviter := dbtest.User(t, inviting, inviting)
	invitee := dbtest.Unique("new.hire") + "@example.test"
	role := dbtest.Role(t, inviting, "user.read")
	invites := invite.NewService(pool, &dbtest.Mailbox{}, 0, "https://console.example.test")
	inv, _, err := invites.Create(ctx, invite.CreateInput{TenantID: inviting, Email: invitee, RoleID: &role}, audit.Actor{UserID: &inviter.ID, Type: "user"})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}

	tenant := openTenant(t)
	addProvider(t, f, tenant, "corp")
	if _, q := redirectQuery(t, f.signIn(t, "corp", "/social/corp/start?tenant_id="+tenant.String(), claims(invitee))); q.Get("code") == "" {
		t.Fatalf("sign-up through the organisation's provider: %v; want a one-time code", q)
	}
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM "user".users WHERE email = $1`, invitee).Scan(&id); err != nil {
		t.Fatalf("the account the sign-up created: %v", err)
	}

	if list, err := invites.ListForUser(ctx, id); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
		t.Errorf("the inbox of an address only the provider asserted = %+v, %v; want %v", list, err, errs.ErrInviteEmailNotVerified)
	}
	if _, err := invites.AcceptAuthenticatedByID(ctx, id, inv.ID, audit.Actor{}); !errors.Is(err, errs.ErrInviteEmailNotVerified) {
		t.Errorf("accepting from the inbox: %v; want %v", err, errs.ErrInviteEmailNotVerified)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, id, inviting); n != 0 {
		t.Errorf("the account holds %d roles in the inviting organisation, want none", n)
	}
}

// TestSocialSignUpRefusedOnADomainAnotherOrganisationManages checks that no
// provider of an organisation, whatever its kind, creates an account on a
// domain another organisation verified, or below it, while the organisation
// that manages the domain still can. The browser is told no more than that
// the sign-in failed.
func TestSocialSignUpRefusedOnADomainAnotherOrganisationManages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	tenant, manager := openTenant(t), openTenant(t)
	domain := dbtest.Domain(t, manager)

	f := newSocialFixture(t)
	addProvider(t, f, tenant, "corp")
	taken := dbtest.Unique("x") + "@" + domain
	target, q := redirectQuery(t, f.signIn(t, "corp", "/social/corp/start?tenant_id="+tenant.String(), claims(taken)))
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, taken); target != "https://login.example.test/sign-in" || q.Get("error") != "social" || q.Get("code") != "" || n != 0 {
		t.Errorf("sign-up through the routes went to %s %v, %d accounts; want the hosted login with error=social and no account", target, q, n)
	}

	for _, provider := range []string{"okta", "github"} {
		for _, host := range []string{domain, "eu." + domain} {
			email := dbtest.Unique("x") + "@" + host
			_, err := svc.findOrCreateUser(ctx, tenant, provider, claims(email))
			if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, email); !errors.Is(err, errs.ErrUserDomainManaged) || n != 0 {
				t.Errorf("%s sign-up at %s: %v, %d accounts; want %v and no account", provider, host, err, n, errs.ErrUserDomainManaged)
			}
		}
	}
	email := dbtest.Unique("own") + "@" + domain
	if id, err := svc.findOrCreateUser(ctx, manager, "okta", claims(email)); err != nil || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND tenant_id = $2`, id, manager) != 1 {
		t.Errorf("sign-up through the managing organisation's own provider: %v; want an account in it", err)
	}
}

// TestSocialSignUpRefusedOnACapturedDomain checks that once an organisation
// requires single sign-on on its domain, with an active connection, its social
// providers create no account there: new people arrive through the connection.
func TestSocialSignUpRefusedOnACapturedDomain(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := provisioningService(t)
	tenant := openTenant(t)
	domain := dbtest.Domain(t, tenant)
	signUp := func() (string, error) {
		email := dbtest.Unique("x") + "@" + domain
		_, err := svc.findOrCreateUser(ctx, tenant, "github", claims(email))
		return email, err
	}

	if email, err := signUp(); err != nil || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, email) != 1 {
		t.Errorf("sign-up on the organisation's domain before it requires single sign-on: %v; want an account", err)
	}
	requireSSO(t, tenant)
	if email, err := signUp(); !errors.Is(err, errs.ErrAuthSSORequired) || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, email) != 0 {
		t.Errorf("sign-up on a domain that requires single sign-on: %v; want %v and no account", err, errs.ErrAuthSSORequired)
	}
}

// TestSocialDoesNotAdoptAnAdministrator checks that no provider of an
// organisation, whatever its kind, takes over by its address an account that
// owns or administers the organisation, directly or through a group, while a
// member holding only read permissions is still adopted. Through the routes
// the browser is told no more than that the sign-in failed.
func TestSocialDoesNotAdoptAnAdministrator(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := provisioningService(t)
	tenant := dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	account := func(roles ...uuid.UUID) dbtest.Account {
		a := dbtest.UserAt(t, dbtest.Unique("user")+"@"+domain, tenant, tenant)
		for _, role := range roles {
			dbtest.Assign(t, a.ID, tenant, role)
		}
		return a
	}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	grouped := account()
	if _, err := pool.Exec(ctx, `
		WITH g AS (INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, 'Identity team') RETURNING id),
		     r AS (INSERT INTO rbac.group_roles (group_id, tenant_id, role_id) SELECT id, $1, $3 FROM g)
		INSERT INTO tenant.group_members (group_id, user_id, tenant_id) SELECT id, $2, $1 FROM g
	`, tenant, grouped.ID, dbtest.Role(t, tenant, "role.write")); err != nil {
		t.Fatal(err)
	}
	owner := account(ownerRole)
	linked := func(a dbtest.Account) int {
		return dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, a.ID)
	}

	for name, a := range map[string]dbtest.Account{
		"an owner":                               owner,
		"an account holding connection.write":    account(dbtest.Role(t, tenant, "user.read", "connection.write")),
		"a member of a group holding role.write": grouped,
	} {
		for _, provider := range []string{"okta", "github"} {
			if got, err := svc.findOrCreateUser(ctx, tenant, provider, verified(t, a)); !errors.Is(err, errs.ErrSocialAccountAdministers) {
				t.Errorf("%s through %s = %s, %v; want %v", name, provider, got, err, errs.ErrSocialAccountAdministers)
			}
		}
		if n := linked(a); n != 0 {
			t.Errorf("%s was linked to %d providers, want none", name, n)
		}
	}

	reader := account(dbtest.Role(t, tenant, "user.read", "audit.read"))
	if got, err := svc.findOrCreateUser(ctx, tenant, "okta", verified(t, reader)); err != nil || got != reader.ID {
		t.Errorf("an account holding only read permissions = %s, %v; want it adopted", got, err)
	}

	f := newSocialFixture(t)
	addProvider(t, f, tenant, "corp")
	target, q := redirectQuery(t, f.signIn(t, "corp", "/social/corp/start?tenant_id="+tenant.String(), verified(t, owner)))
	if target != "https://login.example.test/sign-in" || q.Get("error") != "social" || q.Get("code") != "" || linked(owner) != 0 {
		t.Errorf("the owner's address through the routes went to %s %v; want the hosted login with error=social and no link", target, q)
	}
}

// TestSocialSignInRefusedOnACapturedDomain checks that once an organisation
// requires single sign-on on its domain, none of its social providers signs a
// member in there, whether their identity is linked already or would be
// adopted by address, and nothing new is linked; a break-glass member still
// signs in.
func TestSocialSignInRefusedOnACapturedDomain(t *testing.T) {
	f := newSocialFixture(t)
	capturing(t, f)
	tenant := dbtest.Tenant(t)
	domain := dbtest.Domain(t, tenant)
	addProvider(t, f, tenant, "corp")
	start := "/social/corp/start?tenant_id=" + tenant.String()
	member := func() (dbtest.Account, userInfo) {
		a := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, tenant, tenant)
		return a, verified(t, a)
	}
	signIn := func(person userInfo) url.Values {
		_, q := redirectQuery(t, f.signIn(t, "corp", start, person))
		return q
	}
	_, linkedAs := member()
	if q := signIn(linkedAs); q.Get("code") == "" {
		t.Fatalf("sign-in before the organisation requires single sign-on: %v; want a code", q)
	}
	exempt, exemptAs := member()
	breakGlass(t, tenant, exempt)
	adopted, adoptedAs := member()

	requireSSO(t, tenant)
	if q := signIn(linkedAs); q.Get("code") != "" || q.Get("error") != "social" {
		t.Errorf("a linked member's sign-in on a captured domain: %v; want error=social and no code", q)
	}
	if q := signIn(adoptedAs); q.Get("code") != "" {
		t.Errorf("adopting a member on a captured domain: %v; want no code", q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1`, adopted.ID); n != 0 {
		t.Errorf("%d identities linked to a member on a captured domain, want none", n)
	}
	if q := signIn(exemptAs); q.Get("code") == "" {
		t.Errorf("a break-glass member's sign-in: %v; want a code", q)
	}
}
