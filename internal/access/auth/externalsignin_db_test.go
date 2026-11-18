//go:build integration

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestExternalSignIn checks that a sign-in whose first factor is checked
// elsewhere gets the lockout, hook, second-factor and risk decisions of a
// password sign-in, answering with the challenge where it needs another step.
func TestExternalSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	a, organization := member(t)
	in := ExternalSignIn{OrganizationID: organization, Account: "test:" + a.Email, Method: "ldap", IP: "192.0.2.10"}
	proved := func(context.Context) (uuid.UUID, bool, error) { return a.ID, false, nil }

	t.Run("signs in", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		risk := &riskStub{}
		svc.SetRiskAssessor(risk)
		res, err := svc.SignInExternal(ctx, in, proved)
		if err != nil || res.Pair == nil {
			t.Fatalf("sign in: %+v, %v", res, err)
		}
		pair := res.Pair
		if pair.UserID != a.ID || pair.OrganizationID == nil || *pair.OrganizationID != organization {
			t.Fatalf("signed in as %s to %v, want %s to %s", pair.UserID, pair.OrganizationID, a.ID, organization)
		}
		if risk.recorded != 1 {
			t.Errorf("a completed sign-in was recorded for risk %d times, want 1", risk.recorded)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded'
			AND resource_id = $1 AND metadata->>'method' = 'ldap'`, pair.SessionID); n != 1 {
			t.Error("the sign-in was not audited with its method")
		}
	})

	t.Run("lockout", func(t *testing.T) {
		svc := newService(t)
		locked := in
		locked.Account = dbtest.Unique("test:locked")
		refused := errors.New("refused")
		for range 5 {
			_, err := svc.SignInExternal(ctx, locked, func(context.Context) (uuid.UUID, bool, error) { return uuid.Nil, true, refused })
			if !errors.Is(err, refused) {
				t.Fatalf("refused credential: %v, want %v", err, refused)
			}
		}
		checked := false
		_, err := svc.SignInExternal(ctx, locked, func(context.Context) (uuid.UUID, bool, error) {
			checked = true
			return a.ID, false, nil
		})
		if !errors.Is(err, errs.ErrAuthAccountLocked) || checked {
			t.Errorf("locked account: %v (checked %v), want %v before any check", err, checked, errs.ErrAuthAccountLocked)
		}
	})

	t.Run("address rules", func(t *testing.T) {
		svc := newService(t)
		svc.SetAddressPolicy(addressFunc(func(context.Context, uuid.UUID, uuid.UUID, string, string) error {
			return errs.ErrAuthAddressNotAllowed
		}))
		checked := false
		_, err := svc.SignInExternal(ctx, in, func(context.Context) (uuid.UUID, bool, error) {
			checked = true
			return a.ID, false, nil
		})
		if !errors.Is(err, errs.ErrAuthAddressNotAllowed) || checked {
			t.Errorf("refused network: %v (checked %v), want %v before any check", err, checked, errs.ErrAuthAddressNotAllowed)
		}
	})

	t.Run("hook", func(t *testing.T) {
		svc := newService(t)
		denied := errs.ErrForbidden.WithDetail("denied by hook")
		var hookOrganization uuid.UUID
		svc.SetLoginHook(hookFunc(func(_ context.Context, organizationID, _ uuid.UUID, _ string) (map[string]any, error) {
			hookOrganization = organizationID
			return nil, denied
		}))
		if _, err := svc.SignInExternal(ctx, in, proved); !errors.Is(err, errs.ErrForbidden) || hookOrganization != organization {
			t.Errorf("hook denies: %v for organization %s, want %v for %s", err, hookOrganization, errs.ErrForbidden, organization)
		}
	})

	t.Run("second factor required", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		required, _ := member(t)
		if _, err := pool.Exec(ctx, `UPDATE account.users SET mfa_required = TRUE WHERE id = $1`, required.ID); err != nil {
			t.Fatalf("require MFA: %v", err)
		}
		res, err := svc.SignInExternal(ctx, in, func(context.Context) (uuid.UUID, bool, error) { return required.ID, false, nil })
		if err != nil || res.Pair != nil || !res.MFARequired || !res.EnrollmentRequired || res.MFAToken == "" {
			t.Fatalf("sign in: %+v, %v; want an enrolment challenge", res, err)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_login_challenges WHERE id = $1 AND first_factor = 'ldap'`, res.MFAToken); n != 1 {
			t.Error("the challenge does not record its first factor")
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, required.ID); n != 0 {
			t.Errorf("a challenged sign-in opened %d sessions", n)
		}
	})

	t.Run("risky", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		svc.SetSender(&dbtest.Mailbox{})
		risk := &riskStub{risky: true}
		svc.SetRiskAssessor(risk)
		if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
		for attempt := range 2 {
			res, err := svc.SignInExternal(ctx, in, proved)
			if err != nil || res.Pair != nil || !res.MFARequired || len(res.Methods) != 1 || res.Methods[0] != "email" {
				t.Fatalf("risky sign-in %d: %+v, %v; want an emailed-code challenge", attempt+1, res, err)
			}
		}
		if risk.recorded != 0 {
			t.Errorf("challenged sign-ins were recorded for risk %d times, so asking again could pass", risk.recorded)
		}
	})
}
