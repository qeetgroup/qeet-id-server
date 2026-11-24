//go:build integration

package authentication

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// passwordsOff is an organization that has switched password sign-in off.
type passwordsOff uuid.UUID

func (p passwordsOff) PasswordEnabled(_ context.Context, organizationID uuid.UUID) (bool, error) {
	return organizationID != uuid.UUID(p), nil
}

// TestHomeOrganizationPasswordSwitchAppliesThroughAnyClient checks that an
// organization that switched passwords off keeps its member from signing in
// with one through another organization's application, as through its own or
// none, and that only the right password learns it.
func TestHomeOrganizationPasswordSwitchAppliesThroughAnyClient(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, home := member(t)
	svc.methods = passwordsOff(home)
	elsewhere := dbtest.Organization(t)
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, $2)`, elsewhere, client); err != nil {
		t.Fatal(err)
	}
	hosted := func(password, clientID string) error {
		_, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: password, IP: freshIP(), ClientID: clientID}, testUserAgent, "", "")
		return err
	}

	for name, clientID := range map[string]string{"no application": "", "another organization's application": client} {
		if err := hosted(testPassword, clientID); !errors.Is(err, errs.ErrAuthMethodDisabled) {
			t.Errorf("the right password through %s: %v, want %v", name, err, errs.ErrAuthMethodDisabled)
		}
	}
	if err := hosted("Wrong-password-1", client); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a wrong password through another organization's application: %v, want %v", err, ErrInvalidCredentials)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d hosted-login sessions opened for an organization without passwords", n)
	}
}

// TestPasswordSignIn checks that the right password signs a user in to their
// organization with a live session, an access token naming it, and an audit record.
func TestPasswordSignIn(t *testing.T) {
	svc := newService(t)
	a, organization := member(t)

	pair := signIn(t, svc, a)
	if pair.UserID != a.ID || pair.OrganizationID == nil || *pair.OrganizationID != organization || pair.RefreshToken == "" {
		t.Fatalf("token pair %+v; want user %s in organization %s with a refresh token", pair, a.ID, organization)
	}
	claims, err := svc.tokens.VerifyAccess(pair.AccessToken)
	if err != nil || claims.UserID != a.ID || claims.OrganizationID != organization || claims.SessionID != pair.SessionID {
		t.Fatalf("access token claims %+v, %v", claims, err)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM auth.sessions WHERE id = $1 AND user_id = $2 AND organization_id = $3 AND revoked_at IS NULL
	`, pair.SessionID, a.ID, organization); n != 1 {
		t.Error("no live session for the sign-in")
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND resource_id = $1 AND organization_id = $2
	`, pair.SessionID, organization); n != 1 {
		t.Error("the sign-in was not audited")
	}
}

// TestPasswordSignInRefused checks that a wrong password, an unknown address
// and a suspended account are refused, and open no session.
func TestPasswordSignInRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, _ := member(t)
	suspended, _ := member(t)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	for _, tc := range []struct {
		name, email, password string
		want                  error
	}{
		{"wrong password", a.Email, "Kx7mQ2vLp9Wy", ErrInvalidCredentials},
		{"unknown address", dbtest.Unique("nobody") + "@example.test", testPassword, ErrInvalidCredentials},
		{"suspended account", suspended.Email, testPassword, errs.ErrAuthAccountInactive},
		{"suspended account, wrong password", suspended.Email, "Kx7mQ2vLp9Wy", ErrInvalidCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.Login(ctx, LoginInput{Email: tc.email, Password: tc.password})
			if !errors.Is(err, tc.want) || res != nil {
				t.Errorf("sign in: %+v, %v; want %v", res, err, tc.want)
			}
		})
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = ANY($1)`, []uuid.UUID{a.ID, suspended.ID}); n != 0 {
		t.Errorf("refused sign-ins opened %d sessions", n)
	}
}

// TestChangePasswordEndsSignIns checks that changing the password keeps the
// current session and ends every other way in: sessions, remembered devices
// and application grants.
func TestChangePasswordEndsSignIns(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.regPolicy = anyPassword{}
	a, organization := member(t)
	current, other := signIn(t, svc, a), signIn(t, svc, a)
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')
	`, a.ID, organization, dbtest.Unique("device")); err != nil {
		t.Fatalf("trusted device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at)
		VALUES ($1, 'app', $2, $3, NOW() + INTERVAL '1 day')
	`, dbtest.Unique("grant"), a.ID, organization); err != nil {
		t.Fatalf("application grant: %v", err)
	}

	mail := &dbtest.Mailbox{}
	svc.sender = mail
	if err := svc.ChangePassword(ctx, ChangePasswordInput{
		UserID: a.ID, KeepSessionID: current.SessionID, Current: testPassword, Next: "Pw4!nKx7mQ2v-new",
	}); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if m := mail.Last(t); m.To != a.Email || m.Subject != "Your password was changed" || strings.Contains(m.Body, "Pw4!nKx7mQ2v-new") {
		t.Errorf("notice %q to %s: %q; want the person told, without the password", m.Subject, m.To, m.Body)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, current.SessionID); n != 1 {
		t.Error("the current session ended")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND revoked_at IS NULL`, other.SessionID); n != 0 {
		t.Error("another session survived")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d remembered devices survived", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, a.ID); n != 0 {
		t.Errorf("%d application grants survived", n)
	}
}

// TestConcurrentSignInsShareASmallPool checks that more sign-ins, and then
// renewals, than the pool has connections all complete when run at once: none
// holds its transaction while it waits for a second connection.
func TestConcurrentSignInsShareASmallPool(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.addresses = ipallow.NewService(pool)
	a, organization := member(t)
	enforceAddressRules(t, organization)
	n := 3 * int(pool.Config().MaxConns)

	pairs := make([]*TokenPair, n)
	for i, err := range concurrently(n, func(i int) (err error) {
		pairs[i], err = svc.IssuePair(ctx, a.ID, organization, "192.0.2.10", "test", "password")
		return err
	}) {
		if err != nil {
			t.Fatalf("sign-in %d: %v", i, err)
		}
	}
	for i, err := range concurrently(n, func(i int) error {
		_, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pairs[i].RefreshToken, IP: "192.0.2.10"})
		return err
	}) {
		if err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
	}
}
