//go:build integration

package oidcsso

import (
	"context"
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
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, organization), s.handler.Mount), http.MethodPatch, "/organizations/"+organization.String()+"/oidc-connections/"+conn.ID.String(), body)
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

// denyPlan is a plan without single sign-on.
type denyPlan struct{}

func (denyPlan) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return false, nil }

// TestOIDCConnectionsOverHTTP checks that an organization creates, lists,
// reads, changes and deletes its connections, refusing invalid input, never
// returning or storing the client secret in the clear, and auditing each
// change; that another organization can neither see nor change them; and that
// a plan without single sign-on can't create one.
func TestOIDCConnectionsOverHTTP(t *testing.T) {
	s := newRP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), s.handler.Mount)
	asOther := dbtest.Serve(dbtest.Principal(dbtest.User(t, other, other).ID, other), s.handler.Mount)
	base := "/organizations/" + organization.String() + "/oidc-connections"
	connection := map[string]any{
		"name": " Okta ", "issuer": " https://acme.okta.example.test ", "client_id": "okta-client", "client_secret": "okta-secret-value",
		"scopes": []string{"email", "groups"},
	}
	with := func(change map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range connection {
			out[k] = v
		}
		for k, v := range change {
			out[k] = v
		}
		return out
	}
	for code, change := range map[string]map[string]any{
		CodeFieldsRequired:    {"client_secret": ""},
		CodeIssuerInvalid:     {"issuer": "https://idp.example.test/?tenant=1"},
		CodeTenantIDsRequired: {"issuer": "https://login.microsoftonline.com/common/v2.0"},
		CodeStatusInvalid:     {"status": "enabled"},
	} {
		refused(t, "create with "+code, dbtest.Do(t, asAdmin, http.MethodPost, base, with(change)), code)
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.Name != "Okta" || conn.Issuer != "https://acme.okta.example.test" || conn.Status != "draft" ||
		conn.OrganizationID != organization || strings.Join(conn.Scopes, " ") != "openid email groups" || conn.ClaimMapping.Email != "email" ||
		conn.RedirectURI != testPublicBase+"/v1/oidc-connections/"+conn.ID.String()+"/callback" {
		t.Fatalf("create: %d %s; want a trimmed draft in the organization with its redirect URI", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "okta-secret-value") {
		t.Error("the client secret was returned")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.oidc_connections WHERE id = $1
		AND position(convert_to('okta-secret-value', 'UTF8') IN client_secret_ct) = 0`, conn.ID); n != 1 {
		t.Error("the client secret is stored in the clear")
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/organizations/"+other.String()+"/oidc-connections", connection); rec.Code != http.StatusCreated {
		t.Fatalf("another organization's create: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil)); len(ids) != 1 || ids[0] != conn.ID {
		t.Errorf("list %v, want only the organization's own %s", ids, conn.ID)
	}
	path := base + "/" + conn.ID.String()
	refused(t, "a malformed ID", dbtest.Do(t, asAdmin, http.MethodGet, base+"/not-a-uuid", nil), CodeIDInvalid)

	for code, change := range map[string]map[string]any{
		CodeStatusInvalid:     {"status": "retired"},
		CodeIssuerInvalid:     {"issuer": "javascript:alert(1)"},
		CodeClaimInvalid:      {"claim_mapping": map[string]any{"email": ""}},
		CodeTenantIDsRequired: {"issuer": "https://login.microsoftonline.com/organizations/v2.0"},
	} {
		refused(t, "update with "+code, dbtest.Do(t, asAdmin, http.MethodPatch, path, change), code)
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{
		"name": "Head office", "status": "active", "client_secret": "rotated-secret", "claim_mapping": map[string]any{"email": "upn", "groups": "roles"},
	})
	var updated Connection
	dbtest.Decode(t, rec, &updated)
	if rec.Code != http.StatusOK || updated.Name != "Head office" || updated.Status != "active" ||
		updated.ClaimMapping.Email != "upn" || updated.ClaimMapping.Groups != "roles" || updated.ClaimMapping.Name != "name" {
		t.Errorf("rename, activate and remap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, base+"/"+uuid.NewString(), map[string]any{"name": "Nobody"}); rec.Code != http.StatusNotFound {
		t.Errorf("update an unknown connection: %d, want 404", rec.Code)
	}

	otherPath := "/organizations/" + other.String() + "/oidc-connections/" + conn.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]any{"name": "Taken"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organization %s on the connection: %d, want 404", method, rec.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if rec := dbtest.Do(t, asOther, method, base, connection); rec.Code != http.StatusForbidden {
			t.Errorf("another organization %s on this organization's connections: %d, want 403", method, rec.Code)
		}
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("get a deleted connection: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2
		AND action LIKE 'oidc_connection.%' AND actor_user_id = $3`, organization, conn.ID, admin.ID); n != 3 {
		t.Errorf("%d connection changes recorded, want created, updated and deleted", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2
		AND action = 'oidc_connection.updated' AND metadata->'fields' ? 'client_secret'`, organization, conn.ID); n != 1 {
		t.Error("the update's record doesn't name the replaced secret")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.oidc_connections WHERE organization_id = $1`, other); n != 1 {
		t.Errorf("another organization's connections: %d, want its one untouched", n)
	}

	s.svc.SetPlanGate(denyPlan{})
	rec = dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("create on a plan without single sign-on: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}
}
