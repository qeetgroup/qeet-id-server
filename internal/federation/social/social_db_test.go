//go:build integration

package social

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestSocialSignInAdoptsOnlyAnAccountInTheOrganization checks that a verified
// address adopts an existing account only in its home organization: an organization where
// it merely holds a role, like any other, is refused, so that organization's provider
// can't sign a guest in and switch into the guest's home.
func TestSocialSignInAdoptsOnlyAnAccountInTheOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), nil, "https://api.id.qeet.in")
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
		t.Errorf("sign-in to the home tenant = %s, %v; want the account %s", got, err, account.ID)
	}
	for name, organization := range map[string]uuid.UUID{"joined": joined, "another": other} {
		if got, err := signIn(organization); !errors.Is(err, errs.ErrSocialAccountNotInOrganization) {
			t.Errorf("sign-in to the %s tenant = %s, %v; want %v", name, got, err, errs.ErrSocialAccountNotInOrganization)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND organization_id <> $2`, account.ID, home); n != 0 {
		t.Errorf("another tenant's sign-in linked %d identities", n)
	}
}

// TestSocialSignUpWithOneConnection checks, with only one connection free,
// that a social sign-in with an address nobody holds creates an account where
// the organization allows self-registration, and is refused where it doesn't.
func TestSocialSignUpWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetRegistrationPolicy(authpolicy.NewService(pool))
	svc := NewService(pool, authSvc, "https://api.id.qeet.in")
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
		t.Errorf("sign-up where self-registration is on: %s, %v; want an account in the tenant", id, err)
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
	svc := NewService(pool, nil, "https://api.id.qeet.in")
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
	if _, err := signIn(registered.Email); !errors.Is(err, errs.ErrSocialAccountUnverified) {
		t.Errorf("an unproved account registered otherwise: %v, want %v", err, errs.ErrSocialAccountUnverified)
	}
}

// TestSocialSignInIgnoresConnectionLinks checks that a social provider named
// like a single sign-on kind (saml, ldap, oidc) doesn't find a person linked
// through one of the organization's connections by that subject, so whoever
// controls such a provider can't sign in as them.
func TestSocialSignInIgnoresConnectionLinks(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), nil, "https://api.id.qeet.in")
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
		if got == linked.ID || !errors.Is(err, errs.ErrSocialEmailMissing) {
			t.Errorf("a social %q sign-in with a connection's subject = %s, %v; want no link found", provider, got, err)
		}
	}
}

// TestSocialProviderTrustChangeMustOutrankLinkedAdministrators checks that
// pointing an organization's OpenID Connect provider an owner is linked
// through at another discovery URL, by setting it up again or by changing it,
// is refused to someone who can change providers but doesn't outrank the
// owner, as it could then sign in as them, while other changes aren't, and an
// owner may make it.
func TestSocialProviderTrustChangeMustOutrankLinkedAdministrators(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	f := newSocialFixture(t)
	h := &Handler{Service: f.svc, ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, editor := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "connection.write", "connection.read"))
	as := func(a dbtest.Account, method, path string, body any) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, organization), h.Mount), method, path, body)
		return rec.Code, rec.Body.String()
	}
	discovery := f.idp.URL + "/.well-known/openid-configuration"
	provider := func(url string) map[string]string {
		return map[string]string{"provider": "corp", "client_id": "qeet", "client_secret": "idp-client-secret", "discovery_url": url}
	}
	if status, body := as(owner, http.MethodPost, "/social/providers", provider(discovery)); status != http.StatusOK {
		t.Fatalf("set the provider up: %d %s", status, body)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, subject) VALUES ($1, $2, 'corp', 'owner-subject')`, owner.ID, organization); err != nil {
		t.Fatal(err)
	}
	elsewhere := "https://idp.attacker.example/.well-known/openid-configuration"

	for name, c := range map[string]struct {
		method, path string
		body         any
	}{
		"sets the provider up again elsewhere": {http.MethodPost, "/social/providers", provider(elsewhere)},
		"changes its discovery URL":            {http.MethodPatch, "/social/providers/corp", map[string]string{"discovery_url": elsewhere}},
	} {
		if status, body := as(editor, c.method, c.path, c.body); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTrustChangeOutranks) {
			t.Errorf("an editor %s: %d %s, want 403 %s", name, status, body, errs.CodeRBACTrustChangeOutranks)
		}
	}
	for name, c := range map[string]struct {
		method, path string
		body         any
	}{
		"saves it unchanged":  {http.MethodPost, "/social/providers", provider(discovery)},
		"replaces its secret": {http.MethodPatch, "/social/providers/corp", map[string]any{"client_secret": "rotated-client-secret"}},
	} {
		if status, body := as(editor, c.method, c.path, c.body); status != http.StatusOK {
			t.Errorf("an editor %s: %d %s, want 200", name, status, body)
		}
	}
	if status, body := as(owner, http.MethodPatch, "/social/providers/corp", map[string]string{"discovery_url": f.idp.URL + "/v2/.well-known/openid-configuration"}); status != http.StatusOK {
		t.Errorf("an owner changes its discovery URL: %d %s, want 200", status, body)
	}
}

// TestUnlinkingAnOwnersSocialIdentityNeedsToOutrankThem checks that an
// administrator who may unlink members' social sign-ins can't unlink an
// owner's, nor that of a member holding a permission they don't, while an
// owner can.
func TestUnlinkingAnOwnersSocialIdentityNeedsToOutrankThem(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	f := newSocialFixture(t)
	h := &Handler{Service: f.svc, ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', TRUE) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, otherOwner := dbtest.User(t, organization), dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, otherOwner.ID, organization, ownerRole)
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "user.read", "user.write"))
	billing := dbtest.User(t, organization)
	dbtest.Assign(t, billing.ID, organization, dbtest.Role(t, organization, "billing.write"))
	member := dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `INSERT INTO organization.social_providers (organization_id, provider, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, 'google', 'id', '\x00', '\x00')`, organization); err != nil {
		t.Fatal(err)
	}
	identity := func(a dbtest.Account) string {
		t.Helper()
		dbtest.SetPassword(t, a.ID, dbtest.Unique("Kx7mQ2vLp9Wz"))
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, subject) VALUES ($1, $2, 'google', $3) RETURNING id`,
			a.ID, organization, dbtest.Unique("subject")).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return "/social/identities/" + id.String()
	}
	unlink := func(as dbtest.Account, path string) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(as.ID, organization), h.Mount), http.MethodDelete, path, nil)
		return rec.Code, rec.Body.String()
	}

	owners := identity(owner)
	if status, body := unlink(admin, owners); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetIsOwner) {
		t.Errorf("an administrator unlinks an owner's sign-in: %d %s, want 403 %s", status, body, errs.CodeRBACTargetIsOwner)
	}
	if status, body := unlink(admin, identity(billing)); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetOutranks) {
		t.Errorf("an administrator unlinks the sign-in of someone holding billing.write: %d %s, want 403 %s", status, body, errs.CodeRBACTargetOutranks)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = ANY($1)`, []uuid.UUID{owner.ID, billing.ID}); n != 2 {
		t.Errorf("%d of the outranking people's sign-ins left, want both", n)
	}
	if status, body := unlink(admin, identity(member)); status != http.StatusNoContent {
		t.Errorf("an administrator unlinks a member's sign-in: %d %s, want 204", status, body)
	}
	if status, body := unlink(otherOwner, owners); status != http.StatusNoContent {
		t.Errorf("an owner unlinks another owner's sign-in: %d %s, want 204", status, body)
	}
	if status, _ := unlink(admin, "/social/identities/"+uuid.NewString()); status != http.StatusNotFound {
		t.Errorf("unlink an identity that doesn't exist: %d, want 404", status)
	}
}
