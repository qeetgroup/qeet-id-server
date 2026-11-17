//go:build integration

package oidcsso

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestOIDCTrustChangeMustOutrankLinkedAdministrators checks that pointing a
// connection an owner is linked to at another issuer, discovery URL or client
// is refused to someone who can change connections but doesn't outrank the
// owner, as it could then sign in as them, while renaming it isn't, and an
// owner may make the change.
func TestOIDCTrustChangeMustOutrankLinkedAdministrators(t *testing.T) {
	s := newRP(t)
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	s.handler.ActOnCheck = rbac.NewRepository(pool).CheckActOn
	idp, other := newFakeIdP(t), newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	linked, owner := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	for _, a := range []dbtest.Account{linked, owner} {
		dbtest.Assign(t, a.ID, organization, ownerRole)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject) VALUES ($1, $2, 'oidc', $3, 'entra|owner')`,
		linked.ID, organization, conn.ID); err != nil {
		t.Fatal(err)
	}
	editor := dbtest.User(t, organization, organization)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "connection.write", "connection.read"))
	patch := func(a dbtest.Account, body map[string]any) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, organization), s.handler.Mount), http.MethodPatch, "/tenants/"+organization.String()+"/oidc-connections/"+conn.ID.String(), body)
		return rec.Code, rec.Body.String()
	}

	for name, body := range map[string]map[string]any{
		"discovery URL": {"discovery_url": other.URL + "/.well-known/openid-configuration"},
		"issuer":        {"issuer": other.URL},
		"client":        {"client_id": "another-client"},
	} {
		if status, got := patch(editor, body); status != http.StatusForbidden || !strings.Contains(got, errs.CodeRBACTrustChangeOutranks) {
			t.Errorf("an editor changes the %s of a connection an owner is linked to: %d %s, want 403 %s", name, status, got, errs.CodeRBACTrustChangeOutranks)
		}
	}
	if status, got := patch(editor, map[string]any{"name": "Entra (EU)", "issuer": idp.URL}); status != http.StatusOK {
		t.Errorf("an editor renames it, its issuer unchanged: %d %s, want 200", status, got)
	}
	if status, got := patch(owner, map[string]any{"issuer": other.URL}); status != http.StatusOK {
		t.Errorf("an owner points it at another issuer: %d %s, want 200", status, got)
	}
}
