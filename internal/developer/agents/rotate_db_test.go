//go:build integration

package agent

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRotatingAnAgentNeedsItsScopes checks that rotating an agent's secret
// hands its scopes to whoever rotates it, so it is held to the rule for
// creating one: a developer can't rotate one carrying role.write, and its
// secret stays as it was, while one carrying only their own scopes rotates.
func TestRotatingAnAgentNeedsItsScopes(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	svc := NewService(pool, dbtest.Issuer(t))
	create := func(scopes ...string) uuid.UUID {
		t.Helper()
		a, err := svc.Create(ctx, organization, dbtest.Unique("agent"), scopes, 0, developer.ID, audit.Actor{UserID: &developer.ID, Type: "user"})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	secret := func(id uuid.UUID) string {
		t.Helper()
		var hash string
		if err := pool.QueryRow(ctx, `SELECT secret_hash FROM auth.agents WHERE organization_id = $1 AND id = $2`, organization, id).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: svc, GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	rotate := func(id uuid.UUID) (int, string) {
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/agents/"+id.String()+"/rotate-secret", nil)
		return rec.Code, rec.Body.String()
	}

	powerful := create("user.read", "role.write")
	before := secret(powerful)
	if status, body := rotate(powerful); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACGrantExceedsCaller) || strings.Contains(body, `"secret"`) {
		t.Errorf("rotate an agent carrying role.write: %d %s, want 403 %s and no secret", status, body, errs.CodeRBACGrantExceedsCaller)
	}
	if secret(powerful) != before {
		t.Error("the refused rotation changed the agent's secret")
	}
	if status, body := rotate(create("user.read")); status != http.StatusOK {
		t.Errorf("rotate an agent carrying only the developer's scope: %d %s, want 200", status, body)
	}
}
