//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// withChanges returns a copy of body with change applied.
func withChanges(body, change map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	for k, v := range change {
		out[k] = v
	}
	return out
}

// TestSAMLConnectionsOverHTTP checks that an organization creates, lists,
// reads, tests, changes and deletes its IdP connections, refusing invalid
// input and auditing each change, and that another organization can neither
// see nor change them.
func TestSAMLConnectionsOverHTTP(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin, otherAdmin := dbtest.User(t, organization, organization), dbtest.User(t, other, other)
	h := &Handler{Service: NewService(dbtest.Pool(t), nil, testAppBase), PublicBaseURL: testPublicBase}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	public := chi.NewRouter()
	h.MountPublic(public)
	base := "/organizations/" + organization.String() + "/saml"
	cert, _ := selfSignedCert(t)
	connection := map[string]any{
		"name": " Okta ", "idp_entity_id": "https://idp.example.test", "idp_sso_url": " https://idp.example.test/sso ",
		"idp_certificate": cert, "email_attribute": "email",
	}

	for code, change := range map[string]map[string]any{
		CodeConnectionFieldsRequired: {"idp_entity_id": " "},
		CodeCertificateInvalid:       {"idp_certificate": "not a certificate"},
		CodeSSOURLInvalid:            {"idp_sso_url": "http://idp.example.test/sso"},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, withChanges(connection, change)); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("create with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), code)
		}
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.Name != "Okta" || conn.IdpSSOURL != "https://idp.example.test/sso" ||
		conn.Status != "draft" || conn.AllowIdPInitiated || conn.OrganizationID != organization {
		t.Fatalf("create: %d %s; want a trimmed draft in the organization", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/organizations/"+other.String()+"/saml", connection); rec.Code != http.StatusCreated {
		t.Fatalf("another organization's create: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil)); len(ids) != 1 || ids[0] != conn.ID {
		t.Errorf("list %v, want only the organization's own %s", ids, conn.ID)
	}
	path := base + "/" + conn.ID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), conn.ID.String()) {
		t.Errorf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, base+"/not-a-uuid", nil); !strings.Contains(rec.Body.String(), CodeIDInvalid) {
		t.Errorf("get with a malformed ID: %d %s, want %s", rec.Code, rec.Body.String(), CodeIDInvalid)
	}

	var result TestResult
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, path+"/test", nil), &result)
	if !result.OK || len(result.Checks) != 5 {
		t.Errorf("test a complete connection: %+v, want five checks passed", result)
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"email_attribute": "", "allow_idp_initiated": true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allow_idp_initiated":true`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	result = TestResult{}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, path+"/test", nil), &result)
	if result.OK {
		t.Errorf("test a connection without an email mapping: %+v, want a failed check", result)
	}
	for code, change := range map[string]map[string]any{
		CodeStatusInvalid:      {"status": "retired"},
		CodeSSOURLInvalid:      {"idp_sso_url": "javascript:alert(1)"},
		CodeCertificateInvalid: {"idp_certificate": "not a certificate"},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, change); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("update with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), code)
		}
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"name": "Head office", "status": "active"})
	var updated Connection
	dbtest.Decode(t, rec, &updated)
	if rec.Code != http.StatusOK || updated.Name != "Head office" || updated.Status != "active" || !updated.AllowIdPInitiated {
		t.Errorf("rename and activate: %d %s; want the opt-in kept", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, base+"/"+uuid.NewString(), map[string]any{"name": "Nobody"}); rec.Code != http.StatusNotFound {
		t.Errorf("update an unknown connection: %d, want 404", rec.Code)
	}

	otherPath := "/organizations/" + other.String() + "/saml/" + conn.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]any{"name": "Taken"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organization %s on the connection: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, otherPath+"/test", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organization testing the connection: %d, want 404", rec.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if rec := dbtest.Do(t, asOther, method, base, connection); rec.Code != http.StatusForbidden {
			t.Errorf("another organization %s on this organization's connections: %d, want 403", method, rec.Code)
		}
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if rec := dbtest.Do(t, asAdmin, method, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s a deleted connection: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, public, http.MethodGet, "/saml/metadata/"+conn.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("metadata of a deleted connection: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2 AND action LIKE 'saml.connection_%' AND actor_user_id = $3`, organization, conn.ID, admin.ID); n != 4 {
		t.Errorf("%d connection changes recorded, want created, two updates and deleted", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_connections WHERE organization_id = $1`, other); n != 1 {
		t.Errorf("another organization's connections: %d, want its one untouched", n)
	}
}

// TestSAMLRegistryRefusesBadInputAsInvalid checks that an unknown status on
// create, or a second SP with an entity ID the organization already serves, is
// refused as the client's mistake.
func TestSAMLRegistryRefusesBadInputAsInvalid(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(dbtest.Pool(t), keyPEM, certPEM, "https://login.id.qeet.in", sessionsByCookie{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: NewService(dbtest.Pool(t), nil, testAppBase), IdP: idp}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	cert, _ := selfSignedCert(t)
	connection := map[string]any{"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso", "idp_certificate": cert, "status": "enabled"}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/organizations/"+organization.String()+"/saml", connection); !strings.Contains(rec.Body.String(), CodeStatusInvalid) {
		t.Errorf("a connection with an unknown status: %d %s, want %s", rec.Code, rec.Body.String(), CodeStatusInvalid)
	}
	providers := "/organizations/" + organization.String() + "/saml-providers"
	provider := map[string]any{"name": "App", "entity_id": "https://sp.example.test", "acs_url": "https://sp.example.test/acs", "status": "enabled"}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, providers, provider); !strings.Contains(rec.Body.String(), CodeStatusInvalid) {
		t.Errorf("an SP with an unknown status: %d %s, want %s", rec.Code, rec.Body.String(), CodeStatusInvalid)
	}
	provider["status"] = "active"
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, providers, provider); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, providers, provider); rec.Code/100 != 4 {
		t.Errorf("a second SP with the same entity ID: %d %s, want a 4xx", rec.Code, rec.Body.String())
	}
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
	organization := dbtest.Organization(t)
	conn, unlinked := sp.connect(t, organization, idp), sp.connect(t, organization, idp)
	linkOwner(t, organization, conn.ID)
	editor := dbtest.User(t, organization, organization)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "connection.write", "connection.read"))
	as := dbtest.Serve(dbtest.Principal(editor.ID, organization), sp.handler.Mount)
	path := func(c Connection) string { return "/organizations/" + organization.String() + "/saml/" + c.ID.String() }

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
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_connection_certificates WHERE connection_id = $1`, conn.ID); n != 1 {
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
