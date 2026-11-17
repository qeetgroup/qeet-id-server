//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// newOwner makes a new owner of tenant.
func newOwner(t *testing.T, tenant uuid.UUID) dbtest.Account {
	t.Helper()
	var ownerRole uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true)
		ON CONFLICT (tenant_id, LOWER(name)) DO UPDATE SET is_system = true RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	a := dbtest.User(t, tenant, tenant)
	dbtest.Assign(t, a.ID, tenant, ownerRole)
	return a
}

// linkOwner makes a new owner of tenant whose account is linked to connection
// conn, as an account single sign-on created and an owner later promoted is.
func linkOwner(t *testing.T, tenant, conn uuid.UUID) dbtest.Account {
	t.Helper()
	a := newOwner(t, tenant)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `INSERT INTO "user".external_identities (user_id, tenant_id, provider, connection_id, subject) VALUES ($1, $2, 'saml', $3, $4)`,
		a.ID, tenant, conn, dbtest.Unique("okta|owner")); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestSAMLTrustChangeMustOutrankLinkedAdministrators checks that changing what a
// connection trusts (another certificate, a new one, its IdP's entity ID, or
// metadata from elsewhere) is refused to someone who can change connections but
// doesn't outrank an administrator linked to it, as that change could sign in
// as them, while the rest of the connection stays theirs to edit and a
// connection with no linked administrator stays theirs to change.
func TestSAMLTrustChangeMustOutrankLinkedAdministrators(t *testing.T) {
	sp := newSPSide(t)
	pool := dbtest.Pool(t)
	sp.handler.ActOnCheck = rbac.NewRepository(pool).CheckActOn
	idp, next := newUpstreamIdP(t), newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn, unlinked := sp.connect(t, tenant, idp), sp.connect(t, tenant, idp)
	linkOwner(t, tenant, conn.ID)
	editor := dbtest.User(t, tenant, tenant)
	dbtest.Assign(t, editor.ID, tenant, dbtest.Role(t, tenant, "connection.write", "connection.read"))
	as := dbtest.Serve(dbtest.Principal(editor.ID, tenant), sp.handler.Mount)
	path := func(c Connection) string { return "/tenants/" + tenant.String() + "/saml/" + c.ID.String() }

	for name, c := range map[string]struct {
		method, suffix string
		body           map[string]any
	}{
		"add a certificate":         {http.MethodPost, "/certificates", map[string]any{"certificate": next.certPEM}},
		"replace the certificate":   {http.MethodPatch, "", map[string]any{"idp_certificate": next.certPEM}},
		"change the IdP entity ID":  {http.MethodPatch, "", map[string]any{"idp_entity_id": "https://idp.attacker.example/metadata"}},
		"apply metadata from paste": {http.MethodPost, "/metadata", map[string]any{"metadata_xml": "<EntityDescriptor/>"}},
	} {
		rec := dbtest.Do(t, as, c.method, path(conn)+c.suffix, c.body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeRBACTrustChangeOutranks) {
			t.Errorf("%s of a connection an owner is linked to: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), errs.CodeRBACTrustChangeOutranks)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_connection_certificates WHERE connection_id = $1`, conn.ID); n != 1 {
		t.Errorf("the connection trusts %d certificates, want its one", n)
	}
	for name, c := range map[string]struct {
		target Connection
		body   map[string]any
	}{
		"rename a connection an owner is linked to":            {conn, map[string]any{"name": "Okta (EU)"}},
		"save its unchanged certificate":                       {conn, map[string]any{"idp_certificate": idp.certPEM}},
		"replace the certificate of one no owner is linked to": {unlinked, map[string]any{"idp_certificate": next.certPEM}},
	} {
		if rec := dbtest.Do(t, as, http.MethodPatch, path(c.target), c.body); rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s, want 200", name, rec.Code, rec.Body.String())
		}
	}
}

// TestSAMLCertificateRolloverByOwnerKeepsLinks checks that an owner, who
// outranks no one but acts on owners, still rolls a connection's certificate
// over, and its linked accounts stay linked.
func TestSAMLCertificateRolloverByOwnerKeepsLinks(t *testing.T) {
	sp := newSPSide(t)
	pool := dbtest.Pool(t)
	sp.handler.ActOnCheck = rbac.NewRepository(pool).CheckActOn
	idp, next := newUpstreamIdP(t), newUpstreamIdP(t)
	tenant := dbtest.Tenant(t)
	conn := sp.connect(t, tenant, idp)
	linked := linkOwner(t, tenant, conn.ID)
	owner := newOwner(t, tenant)
	as := dbtest.Serve(dbtest.Principal(owner.ID, tenant), sp.handler.Mount)
	if rec := dbtest.Do(t, as, http.MethodPost, "/tenants/"+tenant.String()+"/saml/"+conn.ID.String()+"/certificates", map[string]any{"certificate": next.certPEM}); rec.Code != http.StatusCreated {
		t.Fatalf("an owner adds the next certificate: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1 AND connection_id = $2`, linked.ID, conn.ID); n != 1 {
		t.Errorf("the linked owner has %d links to the connection, want 1", n)
	}
}
