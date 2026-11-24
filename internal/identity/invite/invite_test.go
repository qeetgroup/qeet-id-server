package invite

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestNewServiceNeedsItsDependencies checks that the invitation service can't
// be built without its sender, password rules, sign-in methods, seat limit or
// grant check.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	full := Deps{
		Sender: stubSender{}, Rules: stubRules{}, Methods: stubMethods{}, Limits: stubLimits{},
		Grants: func(context.Context, *httpx.Principal, uuid.UUID, uuid.UUID) error { return nil },
	}
	for name, drop := range map[string]func(*Deps){
		"Sender":  func(d *Deps) { d.Sender = nil },
		"Rules":   func(d *Deps) { d.Rules = nil },
		"Methods": func(d *Deps) { d.Methods = nil },
		"Limits":  func(d *Deps) { d.Limits = nil },
		"Grants":  func(d *Deps) { d.Grants = nil },
	} {
		d := full
		drop(&d)
		if svc, err := NewService(&pgxpool.Pool{}, d); err == nil {
			t.Errorf("NewService without %s: %v, nil; want an error", name, svc)
		}
	}
	if _, err := NewService(&pgxpool.Pool{}, full); err != nil {
		t.Errorf("NewService with every dependency: %v", err)
	}
}

type (
	stubSender  struct{ notifier.Sender }
	stubRules   struct{ authpolicy.PasswordRules }
	stubMethods struct {
		authpolicy.SignInMethodsChecker
	}
	stubLimits struct{ entitlements.PlanLimiter }
)
