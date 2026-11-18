//go:build integration

package authentication

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAdminMFARequirementCoversEveryAdministrativePermission checks that an
// organization requiring a second factor of its administrators requires it of
// a member holding any one permission outside the member reads, such as
// user.credentials or session.revoke and not only a *.write one, and not of a
// member holding every member read.
func TestAdminMFARequirementCoversEveryAdministrativePermission(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.mfa = &poolFactors{pool: pool}
	svc.memberPermissions = identitylink.MemberPermissions()
	signInHolding := func(permissions ...string) *LoginResult {
		t.Helper()
		organization := dbtest.Organization(t)
		if _, err := pool.Exec(ctx, `
			INSERT INTO organization.security_policies (organization_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
			VALUES ($1, 'admin_only', 0, NOW())`, organization); err != nil {
			t.Fatal(err)
		}
		a := dbtest.User(t, organization)
		dbtest.SetPassword(t, a.ID, testPassword)
		dbtest.Assign(t, a.ID, organization, dbtest.Role(t, organization, permissions...))
		res, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
		if err != nil {
			t.Fatalf("sign in holding %v: %v", permissions, err)
		}
		return res
	}
	for _, permission := range []string{"user.credentials", "session.revoke", "user.write", "gdpr.write", "secret.read", "connection.write"} {
		if res := signInHolding(permission); !res.EnrollmentRequired || res.Pair != nil {
			t.Errorf("a member holding %s signed in without setting up a second factor: %+v", permission, res)
		}
	}
	if res := signInHolding(identitylink.MemberPermissions()...); res.Pair == nil {
		t.Errorf("a member holding only member reads was asked for a second factor: %+v", res)
	}
}

// TestEnrollmentChallengeWithOneConnection checks that an enrolment challenge
// can be started, and skipped in the grace period to sign in, with only one
// connection free.
func TestEnrollmentChallengeWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.mfa = &poolFactors{pool: pool}
	a, organization := member(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO organization.security_policies (organization_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, 'required', 7, NOW())
	`, organization); err != nil {
		t.Fatalf("require MFA: %v", err)
	}
	res, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.EnrollmentRequired || res.EnrollmentDueAt == nil {
		t.Fatalf("sign in: %+v, %v; want an enrolment challenge that may be skipped", res, err)
	}

	dbtest.LeaveOneConnection(t)
	if _, err := svc.StartMFAEnrollment(ctx, res.MFAToken, "", ""); err != nil {
		t.Fatalf("start enrolment: %v", err)
	}
	pair, _, err := svc.CompleteMFALoginWith(ctx, res.MFAToken, MFAProof{Skip: true}, "", "")
	if err != nil || pair == nil {
		t.Fatalf("skip enrolment: %+v, %v", pair, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.mfa_enrollment_deferred' AND actor_user_id = $1`, a.ID); n != 1 {
		t.Errorf("the skipped enrolment was audited %d times, want 1", n)
	}
}
