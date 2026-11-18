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

// TestSignupRefusedOnADomainAnOrganizationManages checks that neither sign-up
// nor another organization's hosted registration creates an account on a
// domain an organization has verified, or below it, while the managing
// organization's own registration still can; and that the refusal reads
// exactly like the answer for an address that already has an account.
func TestSignupRefusedOnADomainAnOrganizationManages(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.regPolicy = anyPassword{}
	organization, manager := dbtest.Organization(t), dbtest.Organization(t)
	domain := dbtest.Domain(t, manager)
	accounts := func(email string) int {
		return dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email)
	}

	for _, host := range []string{domain, "eu." + domain} {
		email := dbtest.Unique("x") + "@" + host
		if _, _, _, err := svc.Signup(ctx, SignupInput{Email: email, Password: testPassword}); !errors.Is(err, errs.ErrUserDomainManaged) {
			t.Errorf("sign-up at %s: %v; want %v", host, err, errs.ErrUserDomainManaged)
		}
		if _, _, err := svc.RegisterInOrganization(ctx, organization, email, testPassword, "", "192.0.2.1", "test"); !errors.Is(err, errs.ErrUserDomainManaged) {
			t.Errorf("registration in another organization at %s: %v; want %v", host, err, errs.ErrUserDomainManaged)
		}
		if n := accounts(email); n != 0 {
			t.Errorf("%d accounts created at %s, want none", n, host)
		}
	}
	own := dbtest.Unique("own") + "@" + domain
	if _, _, err := svc.RegisterInOrganization(ctx, manager, own, testPassword, "", "192.0.2.1", "test"); err != nil || accounts(own) != 1 {
		t.Errorf("registration in the organization that manages the domain: %v; want an account", err)
	}

	h := &Handler{Service: svc, Throttle: passThrough, Bot: noBots{}, Validate: validator.New()}
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
	taken := dbtest.User(t, organization, organization).Email
	for path, body := range map[string]func(email string) map[string]any{
		"/auth/signup": func(e string) map[string]any { return map[string]any{"email": e, "password": testPassword} },
		"/auth/register": func(e string) map[string]any {
			return map[string]any{"organization_id": organization, "email": e, "password": testPassword}
		},
	} {
		want := ask(path, body(taken))
		if got := ask(path, body(dbtest.Unique("x")+"@"+domain)); got != want || want.status != http.StatusUnprocessableEntity {
			t.Errorf("%s on a managed domain answered %+v; want %+v, as for an address that has an account", path, got, want)
		}
	}
}

// TestSignupAnswersAlike checks that signing up with an email that already
// has an account gets the neutral answer, not one naming the email.
func TestSignupAnswersAlike(t *testing.T) {
	svc := newService(t)
	svc.regPolicy = anyPassword{}
	h := &Handler{Service: svc, Throttle: passThrough, Bot: noBots{}, Validate: validator.New()}
	a, organization := member(t)
	srv := chi.NewRouter()
	h.Mount(srv)

	for path, body := range map[string]map[string]any{
		"/auth/signup":   {"email": a.Email, "password": testPassword},
		"/auth/register": {"organization_id": organization, "email": a.Email, "password": testPassword},
	} {
		rec := dbtest.Do(t, srv, http.MethodPost, path, body)
		var got struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		dbtest.Decode(t, rec, &got)
		if rec.Code != http.StatusUnprocessableEntity || got.Error.Code != errs.CodeUnprocessable {
			t.Errorf("%s with a registered email: %d %s, want %d %s", path, rec.Code, rec.Body.String(),
				http.StatusUnprocessableEntity, errs.CodeUnprocessable)
		}
	}
}
