//go:build integration

package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// captureDomain refuses every address on its domain, as an organization that
// requires single sign-on there does.
type captureDomain string

func (d captureDomain) RefuseCaptured(_ context.Context, email string) error {
	if strings.HasSuffix(strings.ToLower(email), "@"+string(d)) {
		return errs.ErrAuthSSORequired
	}
	return nil
}

// TestCapturedAddressesSignInElsewhere checks that an address on a captured
// domain is refused password sign-in, hosted sign-in, sign-up and hosted
// registration with auth.sso_required, the same with or without an account and
// whatever the password, with nothing counted against the lockout or created;
// and that other addresses sign in as before.
func TestCapturedAddressesSignInElsewhere(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetRegistrationPolicy(anyPassword{})
	organization := dbtest.Organization(t)
	domain := dbtest.Unique("acme") + ".example.test"
	svc.SetDomainCapture(captureDomain(domain))
	captured := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	dbtest.SetPassword(t, captured.ID, testPassword)
	nobody := dbtest.Unique("nobody") + "@" + domain

	for _, tc := range []struct{ name, email, password string }{
		{"right password", captured.Email, testPassword},
		{"wrong password", captured.Email, "Kx7mQ2vLp9Wy"},
		{"no account", nobody, testPassword},
	} {
		for range 6 { // past the lockout threshold
			if res, err := svc.Login(ctx, LoginInput{Email: tc.email, Password: tc.password}); !errors.Is(err, errs.ErrAuthSSORequired) || res != nil {
				t.Fatalf("%s: %+v, %v; want %v", tc.name, res, err, errs.ErrAuthSSORequired)
			}
		}
		if _, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: tc.email, Password: tc.password}, "test", "", ""); !errors.Is(err, errs.ErrAuthSSORequired) {
			t.Errorf("%s, hosted: %v; want %v", tc.name, err, errs.ErrAuthSSORequired)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, captured.ID); n != 0 {
		t.Errorf("a captured address opened %d sessions", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_failed' AND resource_id = $1`, captured.ID); n != 0 {
		t.Errorf("%d failed sign-ins counted for a captured address", n)
	}

	h := &Handler{Service: svc, Validate: validator.New()}
	srv := chi.NewRouter()
	h.Mount(srv)
	for path, body := range map[string]map[string]any{
		"/auth/signup":   {"email": nobody, "password": testPassword},
		"/auth/register": {"organization_id": organization, "email": nobody, "password": testPassword},
	} {
		rec := dbtest.Do(t, srv, http.MethodPost, path, body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeAuthSSORequired) {
			t.Errorf("%s on a captured domain: %d %s, want 403 %s", path, rec.Code, rec.Body.String(), errs.CodeAuthSSORequired)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, nobody); n != 0 {
		t.Error("sign-up created an account on a captured domain")
	}

	a, _ := member(t)
	signIn(t, svc, a)
	// Once the domain is no longer captured, the account isn't locked.
	svc.SetDomainCapture(nil)
	signIn(t, svc, captured)
}
