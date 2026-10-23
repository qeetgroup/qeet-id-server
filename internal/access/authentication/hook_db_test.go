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

// TestEverySignInRunsTheLoginHook checks that the organisation's login hook
// decides every way of signing in, once each, for the organisation signed in
// to, and that its refusal opens no session.
func TestEverySignInRunsTheLoginHook(t *testing.T) {
	ctx := dbtest.Context(t)
	a, tenant := member(t)
	sessions := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, a.ID) +
			dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID)
	}
	ways := map[string]func(svc *Service) error{
		"token pair (SAML, passkey)": func(svc *Service) error {
			_, err := svc.IssuePair(ctx, a.ID, tenant, "192.0.2.1", "test", "saml")
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
			_, err := svc.BeginSocialSignIn(ctx, a.ID, tenant, "192.0.2.1", "test")
			return err
		},
		"hosted social": func(svc *Service) error {
			_, err := svc.BeginSocialLoginSession(ctx, a.ID, tenant, "192.0.2.1", "test", "", "")
			return err
		},
		"magic link": func(svc *Service) error {
			_, err := svc.BeginMagicLinkSignIn(ctx, a.ID, tenant, "192.0.2.1", "test")
			return err
		},
		"hosted magic link": func(svc *Service) error {
			_, err := svc.BeginMagicLinkSession(ctx, a.ID, tenant, "192.0.2.1", "test", "", "")
			return err
		},
	}
	for name, signIn := range ways {
		t.Run(name, func(t *testing.T) {
			svc := newService(t)
			var calls int
			var asked uuid.UUID
			svc.SetLoginHook(hookFunc(func(_ context.Context, tenantID, _ uuid.UUID, _ string) (map[string]any, error) {
				calls++
				asked = tenantID
				return nil, errs.ErrAuthHookDenied
			}))
			before := sessions()
			if err := signIn(svc); !errors.Is(err, errs.ErrAuthHookDenied) {
				t.Fatalf("refused by the hook: %v, want %v", err, errs.ErrAuthHookDenied)
			}
			if calls != 1 || asked != tenant {
				t.Errorf("hook called %d times for %s, want once for %s", calls, asked, tenant)
			}
			if n := sessions(); n != before {
				t.Errorf("a refused sign-in opened %d sessions", n-before)
			}

			svc.SetLoginHook(hookFunc(func(context.Context, uuid.UUID, uuid.UUID, string) (map[string]any, error) {
				calls++
				return nil, nil
			}))
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
