//go:build integration

package authentication

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSignInsAndRenewalsMakeAPersonMonthlyActive checks that signing in to an
// organization makes the person active in it this month, once however often
// they sign in, and that renewing the session does too.
func TestSignInsAndRenewalsMakeAPersonMonthlyActive(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, organization := member(t)
	active := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.monthly_active_users
			WHERE organization_id = $1 AND user_id = $2 AND month = date_trunc('month', NOW() AT TIME ZONE 'UTC')::date`, organization, a.ID)
	}

	pair := signIn(t, svc, a)
	signIn(t, svc, a)
	if n := active(); n != 1 {
		t.Fatalf("after two sign-ins: %d rows, want 1", n)
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM organization.monthly_active_users WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n := active(); n != 1 {
		t.Fatalf("after a renewal: %d rows, want 1", n)
	}
}

// TestEverySignInRunsTheLoginHook checks that the organization's login hook
// decides every way of signing in, once each, for the organization signed in
// to, and that its refusal opens no session.
func TestEverySignInRunsTheLoginHook(t *testing.T) {
	ctx := dbtest.Context(t)
	a, organization := member(t)
	sessions := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID) +
			dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID)
	}
	ways := map[string]func(svc *Service) error{
		"token pair (SAML, passkey)": func(svc *Service) error {
			_, err := svc.IssuePair(ctx, a.ID, organization, "192.0.2.1", "test", "saml")
			return err
		},
		"hosted session": func(svc *Service) error {
			_, err := svc.CreateLoginSession(ctx, a.ID, "192.0.2.1", "test")
			return err
		},
		"hosted passkey session": func(svc *Service) error {
			_, err := svc.CreatePasskeyLoginSession(ctx, a.ID, "192.0.2.1", "test")
			return err
		},
		"social": func(svc *Service) error {
			_, err := svc.BeginSocialSignIn(ctx, a.ID, organization, "192.0.2.1", "test")
			return err
		},
		"hosted social": func(svc *Service) error {
			_, err := svc.BeginSocialLoginSession(ctx, a.ID, organization, "192.0.2.1", "test", "", "")
			return err
		},
		"magic link": func(svc *Service) error {
			_, err := svc.BeginMagicLinkSignIn(ctx, a.ID, organization, "192.0.2.1", "test")
			return err
		},
		"hosted magic link": func(svc *Service) error {
			_, err := svc.BeginMagicLinkSession(ctx, a.ID, organization, "192.0.2.1", "test", "", "")
			return err
		},
	}
	for name, signIn := range ways {
		t.Run(name, func(t *testing.T) {
			svc := newService(t)
			var calls int
			var asked uuid.UUID
			svc.loginHook = hookFunc(func(_ context.Context, organizationID, _ uuid.UUID, _ string) (map[string]any, error) {
				calls++
				asked = organizationID
				return nil, errs.ErrAuthHookDenied
			})
			before := sessions()
			if err := signIn(svc); !errors.Is(err, errs.ErrAuthHookDenied) {
				t.Fatalf("refused by the hook: %v, want %v", err, errs.ErrAuthHookDenied)
			}
			if calls != 1 || asked != organization {
				t.Errorf("hook called %d times for %s, want once for %s", calls, asked, organization)
			}
			if n := sessions(); n != before {
				t.Errorf("a refused sign-in opened %d sessions", n-before)
			}

			svc.loginHook = hookFunc(func(context.Context, uuid.UUID, uuid.UUID, string) (map[string]any, error) {
				calls++
				return nil, nil
			})
			calls = 0
			if err := signIn(svc); err != nil {
				t.Fatalf("allowed by the hook: %v", err)
			}
			if calls != 1 {
				t.Errorf("an allowed sign-in ran the hook %d times, want once", calls)
			}
		})
	}
}
