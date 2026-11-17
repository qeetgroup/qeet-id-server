//go:build integration

package principal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRotatingAPrincipalNeedsItsScopes checks that rotating a service
// principal's secret hands its scopes to whoever rotates it, so it is held to
// the rule for creating one: a developer can't rotate one carrying role.write,
// and its secret stays as it was, while one carrying only their own scopes
// rotates.
func TestRotatingAPrincipalNeedsItsScopes(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	svc := NewService(pool, dbtest.Issuer(t))
	create := func(scopes ...string) uuid.UUID {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		p, _, err := svc.Create(ctx, tx, CreateInput{OrganizationID: organization, Name: dbtest.Unique("ci"), Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	secret := func(id uuid.UUID) string {
		t.Helper()
		var hash string
		if err := pool.QueryRow(ctx, `SELECT secret_hash FROM auth.service_principals WHERE organization_id = $1 AND id = $2`, organization, id).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: svc, GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	rotate := func(id uuid.UUID) (int, string) {
		rec := dbtest.Do(t, h, http.MethodPost, "/tenants/"+organization.String()+"/service-principals/"+id.String()+"/rotate-secret", nil)
		return rec.Code, rec.Body.String()
	}

	powerful := create("user.read", "role.write")
	before := secret(powerful)
	if status, body := rotate(powerful); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACGrantExceedsCaller) || strings.Contains(body, "client_secret") {
		t.Errorf("rotate a principal carrying role.write: %d %s, want 403 %s and no secret", status, body, errs.CodeRBACGrantExceedsCaller)
	}
	if secret(powerful) != before {
		t.Error("the refused rotation changed the principal's secret")
	}
	if status, body := rotate(create("user.read")); status != http.StatusOK {
		t.Errorf("rotate a principal carrying only the developer's scope: %d %s, want 200", status, body)
	}
}
