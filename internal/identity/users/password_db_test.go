//go:build integration

package user_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAdminPasswordSetEndsEverySignIn checks that an administrator setting a
// user's password ends the user's sessions, application grants and trusted
// devices.
func TestAdminPasswordSetEndsEverySignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	target := dbtest.User(t, tenant, tenant)
	for _, seed := range []struct{ what, sql string }{
		{"session", `INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2)`},
		{"application grant", `INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, expires_at)
			VALUES (gen_random_uuid()::text, 'test-app', $1, $2, NOW() + INTERVAL '1 day')`},
		{"trusted device", `INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, expires_at)
			VALUES ($1, $2, gen_random_uuid()::text, NOW() + INTERVAL '1 day')`},
	} {
		if _, err := pool.Exec(ctx, seed.sql, target.ID, tenant); err != nil {
			t.Fatalf("create %s: %v", seed.what, err)
		}
	}

	users := user.NewRepository(pool)
	h := &user.Handler{
		Repo:           users,
		Validate:       validator.New(validator.WithRequiredStructEnabled()),
		PasswordPolicy: func(context.Context, uuid.UUID, string, string) error { return nil },
		SignIns:        auth.NewService(pool, users, dbtest.Issuer(t)),
	}
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	rec := dbtest.Do(t, as, http.MethodPost, "/users/"+target.ID.String()+"/password", map[string]any{"password": "Kx7mQ2vLp9Wz-set"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set password: status %d (%s)", rec.Code, rec.Body.String())
	}

	for _, left := range []struct{ what, sql string }{
		{"session", `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`},
		{"application grant", `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`},
		{"trusted device", `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`},
	} {
		if n := dbtest.Count(t, left.sql, target.ID); n != 0 {
			t.Errorf("%d %s rows are still live after the password was set", n, left.what)
		}
	}
}
