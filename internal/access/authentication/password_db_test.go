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

// passwordsOff is an organisation that has switched password sign-in off.
type passwordsOff uuid.UUID

func (p passwordsOff) PasswordEnabled(_ context.Context, tenantID uuid.UUID) (bool, error) {
	return tenantID != uuid.UUID(p), nil
}

// TestHomeOrganisationPasswordSwitchAppliesThroughAnyClient checks that an
// organisation that switched passwords off keeps its member from signing in
// with one through another organisation's application, as through its own or
// none, and that only the right password learns it.
func TestHomeOrganisationPasswordSwitchAppliesThroughAnyClient(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, home := member(t)
	svc.SetMethodPolicy(passwordsOff(home))
	elsewhere := dbtest.Tenant(t)
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (tenant_id, client_id, name) VALUES ($1, $2, $2)`, elsewhere, client); err != nil {
		t.Fatal(err)
	}
	hosted := func(password, clientID string) error {
		_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: password, IP: freshIP(), ClientID: clientID}, testUserAgent, "", "")
		return err
	}

	for name, clientID := range map[string]string{"no application": "", "another organisation's application": client} {
		if err := hosted(testPassword, clientID); !errors.Is(err, errs.ErrAuthMethodDisabled) {
			t.Errorf("the right password through %s: %v, want %v", name, err, errs.ErrAuthMethodDisabled)
		}
	}
	if err := hosted("Wrong-password-1", client); !errors.Is(err, errs.ErrAuthInvalidCredentials) {
		t.Errorf("a wrong password through another organisation's application: %v, want %v", err, errs.ErrAuthInvalidCredentials)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d hosted-login sessions opened for an organisation without passwords", n)
	}
}
