//go:build integration

package apikey

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAPIKeysCarryOnlyTheCreatorsAuthority checks that a credential is created
// only with scopes its creator holds: a developer can't mint one with role.write.
func TestAPIKeysCarryOnlyTheCreatorsAuthority(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: NewService(pool), GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	path := "/api-keys"

	body := func(scopes ...string) map[string]any {
		return map[string]any{"name": "ci-deploy", "scopes": scopes}
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read", "role.write")); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeRBACGrantExceedsCaller) || !strings.Contains(rec.Body.String(), "role.write") {
		t.Errorf("create with role.write: %d %s, want 403 %s naming role.write", rec.Code, rec.Body.String(), errs.CodeRBACGrantExceedsCaller)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read")); rec.Code != http.StatusCreated {
		t.Errorf("create with the creator's own scope: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE organization_id = $1`, organization); n != 1 {
		t.Errorf("%d credentials stored, want only the permitted one", n)
	}
}
