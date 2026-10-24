//go:build integration

package social

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestSocialSignInAdoptsOnlyAnAccountInTheTenant checks that a verified
// address adopts an existing account only in its home tenant: a tenant where
// it merely holds a role, like any other, is refused, so that tenant's provider
// can't sign a guest in and switch into the guest's home.
func TestSocialSignInAdoptsOnlyAnAccountInTheTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), nil, "https://api.id.qeet.in")
	home, joined, other := dbtest.Tenant(t), dbtest.Tenant(t), dbtest.Tenant(t)
	account := dbtest.User(t, home, joined)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, account.ID); err != nil {
		t.Fatal(err)
	}
	signIn := func(tenant uuid.UUID) (uuid.UUID, error) {
		return svc.findOrCreateUser(ctx, tenant, "google", userInfo{Subject: uuid.NewString(), Email: account.Email, EmailVerified: true})
	}

	if got, err := signIn(home); err != nil || got != account.ID {
		t.Errorf("sign-in to the home tenant = %s, %v; want the account %s", got, err, account.ID)
	}
	for name, tenant := range map[string]uuid.UUID{"joined": joined, "another": other} {
		if got, err := signIn(tenant); !errors.Is(err, errs.ErrSocialAccountNotInTenant) {
			t.Errorf("sign-in to the %s tenant = %s, %v; want %v", name, got, err, errs.ErrSocialAccountNotInTenant)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1 AND tenant_id <> $2`, account.ID, home); n != 0 {
		t.Errorf("another tenant's sign-in linked %d identities", n)
	}
}

// TestSocialSignUpWithOneConnection checks, with only one connection free,
// that a social sign-in with an address nobody holds creates an account where
// the organisation allows self-registration, and is refused where it doesn't.
func TestSocialSignUpWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetRegistrationPolicy(authpolicy.NewService(pool))
	svc := NewService(pool, authSvc, "https://api.id.qeet.in")
	open, closed := dbtest.Tenant(t), dbtest.Tenant(t)
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.auth_policy (tenant_id, self_registration_enabled) VALUES ($1, TRUE)`, open); err != nil {
		t.Fatalf("policy: %v", err)
	}
	signUp := func(tenant uuid.UUID) (string, uuid.UUID, error) {
		email := dbtest.Unique("social") + "@example.test"
		id, err := svc.findOrCreateUser(ctx, tenant, "google", userInfo{Subject: uuid.NewString(), Email: email, EmailVerified: true})
		return email, id, err
	}

	dbtest.LeaveOneConnection(t)
	if email, id, err := signUp(open); err != nil || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND email = $2 AND tenant_id = $3`, id, email, open) != 1 {
		t.Errorf("sign-up where self-registration is on: %s, %v; want an account in the tenant", id, err)
	}
	if email, _, err := signUp(closed); !errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) || dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, email) != 0 {
		t.Errorf("sign-up where self-registration is off: %v; want %v and no account", err, errs.ErrAuthSelfRegistrationDisabled)
	}
}
