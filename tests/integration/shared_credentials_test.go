//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestAnAdministratorCantTakeOverAPersonsOtherOrganisations: a person's one
// account carries the same password and second factors into every
// organisation they belong to, so an administrator of the organisation the
// account calls home could set its password or reset its factors, sign in as
// the person, and switch into their other organisations. Those changes are now
// refused for an account that belongs to another organisation too; for one
// that belongs only to the administrator's organisation they work as before,
// and the person is told.
func TestAnAdministratorCantTakeOverAPersonsOtherOrganisations(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	mail := &mailbox{}
	h := &user.Handler{Repo: users, Validate: validator.New(), Mailer: mail,
		PasswordPolicy: authpolicy.NewService(testPool).ValidateForTenant,
		MFA:            mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")}
	org := createTenant(t, ctx, uniqueSlug("employer"))
	if _, err := testPool.Exec(ctx, `UPDATE tenant.tenants SET name = 'Employer Ltd' WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
	admin := uuid.New()
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", UserID: &admin, TenantID: &org})))
		})
	})
	router.Route("/v1", h.Mount)
	call := func(method, path, body string) (int, string) {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
		var out struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out.Error.Code
	}
	setPassword := func(id uuid.UUID) (int, string) {
		return call(http.MethodPost, "/v1/users/"+id.String()+"/password", `{"password":"An-admin-set-passphrase-5"}`)
	}
	resetFactors := func(id uuid.UUID) (int, string) { return call(http.MethodDelete, "/v1/users/"+id.String()+"/mfa", "") }
	person := func(t *testing.T) (uuid.UUID, string) {
		t.Helper()
		email := uniqueSlug("person") + "@example.com"
		return createTenantUser(t, ctx, org, email), email
	}

	t.Run("an account that also belongs to another organisation is refused", func(t *testing.T) {
		consultant, email := person(t)
		addTenantMembership(t, ctx, consultant, createTenant(t, ctx, uniqueSlug("client")))
		if code, errCode := setPassword(consultant); code != http.StatusForbidden || errCode != "user.credentials_shared" {
			t.Fatalf("set password = %d %s, want 403 user.credentials_shared", code, errCode)
		}
		if code, errCode := resetFactors(consultant); code != http.StatusForbidden || errCode != "user.credentials_shared" {
			t.Fatalf("reset factors = %d %s, want 403 user.credentials_shared", code, errCode)
		}
		var hasPassword bool
		if err := testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth.password_credentials WHERE user_id = $1)`, consultant).Scan(&hasPassword); err != nil || hasPassword {
			t.Fatalf("a password was written anyway (%v, %v)", hasPassword, err)
		}
		if n := mail.count(email); n != 0 {
			t.Fatalf("%d notices sent for refused changes", n)
		}
	})

	t.Run("an account that belongs only here is changed as before, and the person is told", func(t *testing.T) {
		employee, email := person(t)
		addTenantMembership(t, ctx, employee, org)
		if code, errCode := setPassword(employee); code != http.StatusNoContent {
			t.Fatalf("set password = %d %s, want 204", code, errCode)
		}
		if code, errCode := resetFactors(employee); code != http.StatusOK {
			t.Fatalf("reset factors = %d %s, want 200", code, errCode)
		}
		mail.mu.Lock()
		defer mail.mu.Unlock()
		var notices []string
		for _, m := range mail.sent {
			if m.To == email {
				notices = append(notices, m.Subject+" | "+m.Body)
			}
		}
		if len(notices) != 2 || !strings.Contains(notices[0], "new password") || !strings.Contains(notices[1], "two-step verification") ||
			!strings.Contains(notices[0], "Employer Ltd") {
			t.Fatalf("notices = %q, want one for the password and one for the factors, naming the organisation", notices)
		}
	})
}
