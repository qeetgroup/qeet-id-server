//go:build integration

package apikey

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRotatingAKeyNeedsItsScopesHoweverManyKeysThereAre checks that rotating
// an API key is held to its scopes even when the organisation has more keys
// than one list returns: an old key carrying role.write, behind a thousand
// newer ones, doesn't rotate for a developer who lacks it.
func TestRotatingAKeyNeedsItsScopesHoweverManyKeysThereAre(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	developer := dbtest.User(t, tenant)
	dbtest.Assign(t, developer.ID, tenant, dbtest.Role(t, tenant, "apikey.write", "user.read"))
	var old uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO auth.api_keys (tenant_id, name, prefix, key_hash, scopes, created_at)
		VALUES ($1, 'old', $2, 'hash', '{user.read,role.write}', NOW() - INTERVAL '1 day') RETURNING id`,
		tenant, dbtest.Unique("qk")).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.api_keys (tenant_id, name, prefix, key_hash, scopes)
		SELECT $1, 'newer', $2 || n, 'hash', '{user.read}' FROM generate_series(1, 1001) AS n`,
		tenant, dbtest.Unique("qk")); err != nil {
		t.Fatal(err)
	}
	h := dbtest.Serve(dbtest.Principal(developer.ID, tenant),
		(&Handler{Service: NewService(pool), GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+tenant.String()+"/api-keys/"+old.String()+"/rotate", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeRBACGrantExceedsCaller) {
		t.Errorf("rotate an old key carrying role.write: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeRBACGrantExceedsCaller)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE tenant_id = $1 AND rotated_from = $2`, tenant, old); n != 0 {
		t.Errorf("%d replacements of the old key were made, want none", n)
	}
}
