//go:build integration

package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSignupRefusedOnADomainAnOrganisationManages checks that neither sign-up
// nor another organisation's hosted registration creates an account on a
// domain an organisation has verified, or below it, while the managing
// organisation's own registration still can; and that the refusal reads
// exactly like the answer for an address that already has an account.
func TestSignupRefusedOnADomainAnOrganisationManages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetRegistrationPolicy(anyPassword{})
	tenant, manager := dbtest.Tenant(t), dbtest.Tenant(t)
	domain := dbtest.Domain(t, manager)
	accounts := func(email string) int {
		return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email)
	}

	for _, host := range []string{domain, "eu." + domain} {
		email := dbtest.Unique("x") + "@" + host
		if _, _, _, err := svc.Signup(ctx, SignupInput{Email: email, Password: testPassword}); !errors.Is(err, errs.ErrUserDomainManaged) {
			t.Errorf("sign-up at %s: %v; want %v", host, err, errs.ErrUserDomainManaged)
		}
		if _, _, err := svc.RegisterInTenant(ctx, tenant, email, testPassword, "", "192.0.2.1", "test"); !errors.Is(err, errs.ErrUserDomainManaged) {
			t.Errorf("registration in another organisation at %s: %v; want %v", host, err, errs.ErrUserDomainManaged)
		}
		if n := accounts(email); n != 0 {
			t.Errorf("%d accounts created at %s, want none", n, host)
		}
	}
	own := dbtest.Unique("own") + "@" + domain
	if _, _, err := svc.RegisterInTenant(ctx, manager, own, testPassword, "", "192.0.2.1", "test"); err != nil || accounts(own) != 1 {
		t.Errorf("registration in the organisation that manages the domain: %v; want an account", err)
	}

	h := &Handler{Service: svc, Validate: validator.New()}
	srv := chi.NewRouter()
	h.Mount(srv)
	type answer struct {
		status        int
		code, message string
	}
	ask := func(path string, body map[string]any) answer {
		rec := dbtest.Do(t, srv, http.MethodPost, path, body)
		var got struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		dbtest.Decode(t, rec, &got)
		return answer{rec.Code, got.Error.Code, got.Error.Message}
	}
	taken := dbtest.User(t, tenant, tenant).Email
	for path, body := range map[string]func(email string) map[string]any{
		"/auth/signup": func(e string) map[string]any { return map[string]any{"email": e, "password": testPassword} },
		"/auth/register": func(e string) map[string]any {
			return map[string]any{"tenant_id": tenant, "email": e, "password": testPassword}
		},
	} {
		want := ask(path, body(taken))
		if got := ask(path, body(dbtest.Unique("x")+"@"+domain)); got != want || want.status != http.StatusUnprocessableEntity {
			t.Errorf("%s on a managed domain answered %+v; want %+v, as for an address that has an account", path, got, want)
		}
	}
}
