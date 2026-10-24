//go:build integration

package saml

// Database tests for the admin routes managing an organisation's IdP
// connections and the service providers its IdP serves.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

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

// TestSAMLConnectionsOverHTTP checks that an organisation creates, lists,
// reads, tests, changes and deletes its IdP connections, refusing invalid
// input and auditing each change, and that another organisation can neither
// see nor change them.
func TestSAMLConnectionsOverHTTP(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin, otherAdmin := dbtest.User(t, tenant, tenant), dbtest.User(t, other, other)
	h := &Handler{Service: NewService(dbtest.Pool(t), nil, testAppBase), PublicBaseURL: testPublicBase}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	public := chi.NewRouter()
	h.MountPublic(public)
	base := "/tenants/" + tenant.String() + "/saml"
	cert, _ := selfSignedCert(t)
	connection := map[string]any{
		"name": " Okta ", "idp_entity_id": "https://idp.example.test", "idp_sso_url": " https://idp.example.test/sso ",
		"idp_certificate": cert, "email_attribute": "email",
	}

	for code, change := range map[string]map[string]any{
		errs.CodeSAMLConnectionFieldsRequired: {"idp_entity_id": " "},
		errs.CodeSAMLCertificateInvalid:       {"idp_certificate": "not a certificate"},
		errs.CodeSAMLSSOURLInvalid:            {"idp_sso_url": "http://idp.example.test/sso"},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, withChanges(connection, change)); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("create with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), code)
		}
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.Name != "Okta" || conn.IdpSSOURL != "https://idp.example.test/sso" ||
		conn.Status != "draft" || conn.AllowIdPInitiated || conn.TenantID != tenant {
		t.Fatalf("create: %d %s; want a trimmed draft in the organisation", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/tenants/"+other.String()+"/saml", connection); rec.Code != http.StatusCreated {
		t.Fatalf("another organisation's create: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil)); len(ids) != 1 || ids[0] != conn.ID {
		t.Errorf("list %v, want only the organisation's own %s", ids, conn.ID)
	}
	path := base + "/" + conn.ID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), conn.ID.String()) {
		t.Errorf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, base+"/not-a-uuid", nil); !strings.Contains(rec.Body.String(), errs.CodeSAMLIDInvalid) {
		t.Errorf("get with a malformed ID: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLIDInvalid)
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
		errs.CodeSAMLStatusInvalid:      {"status": "retired"},
		errs.CodeSAMLSSOURLInvalid:      {"idp_sso_url": "javascript:alert(1)"},
		errs.CodeSAMLCertificateInvalid: {"idp_certificate": "not a certificate"},
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

	otherPath := "/tenants/" + other.String() + "/saml/" + conn.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]any{"name": "Taken"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organisation %s on the connection: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, otherPath+"/test", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation testing the connection: %d, want 404", rec.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if rec := dbtest.Do(t, asOther, method, base, connection); rec.Code != http.StatusForbidden {
			t.Errorf("another organisation %s on this organisation's connections: %d, want 403", method, rec.Code)
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND resource_id = $2 AND action LIKE 'saml.connection_%' AND actor_user_id = $3`, tenant, conn.ID, admin.ID); n != 4 {
		t.Errorf("%d connection changes recorded, want created, two updates and deleted", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_connections WHERE tenant_id = $1`, other); n != 1 {
		t.Errorf("another organisation's connections: %d, want its one untouched", n)
	}
}

// TestSAMLServiceProvidersOverHTTP checks that an organisation registers,
// lists, reads, changes and deletes the service providers its IdP serves,
// refusing invalid input and auditing each change, and that another
// organisation can neither see nor change them.
func TestSAMLServiceProvidersOverHTTP(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin, otherAdmin := dbtest.User(t, tenant, tenant), dbtest.User(t, other, other)
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(dbtest.Pool(t), keyPEM, certPEM, "https://login.id.qeet.in", sessionsByCookie{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: &Service{}, IdP: idp}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	base := "/tenants/" + tenant.String() + "/saml-providers"
	spCert, _ := selfSignedCert(t)
	provider := map[string]any{"name": " App ", "entity_id": " https://sp.example.test ", "acs_url": "https://sp.example.test/acs", "certificate": spCert}

	for code, change := range map[string]map[string]any{
		errs.CodeSAMLSPFieldsRequired:   {"entity_id": " "},
		errs.CodeSAMLACSURLInvalid:      {"acs_url": "http://sp.example.test/acs"},
		errs.CodeSAMLCertificateInvalid: {"certificate": "not a certificate"},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, withChanges(provider, change)); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("register with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), code)
		}
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, provider)
	var sp ServiceProvider
	dbtest.Decode(t, rec, &sp)
	if rec.Code != http.StatusCreated || sp.Name != "App" || sp.EntityID != "https://sp.example.test" || sp.Status != "draft" ||
		sp.NameIDFormat != nameIDEmail || sp.NameIDAttribute != "email" || sp.TenantID != tenant {
		t.Fatalf("register: %d %s; want a trimmed draft with the email NameID defaults", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/tenants/"+other.String()+"/saml-providers", provider); rec.Code != http.StatusCreated {
		t.Fatalf("another organisation registering the same entity: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil)); len(ids) != 1 || ids[0] != sp.ID {
		t.Errorf("list %v, want only the organisation's own %s", ids, sp.ID)
	}
	path := base + "/" + sp.ID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), sp.ID.String()) {
		t.Errorf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, base+"/not-a-uuid", nil); !strings.Contains(rec.Body.String(), errs.CodeSAMLIDInvalid) {
		t.Errorf("get with a malformed ID: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLIDInvalid)
	}
	for code, change := range map[string]map[string]any{
		errs.CodeSAMLStatusInvalid:      {"status": "retired"},
		errs.CodeSAMLACSURLInvalid:      {"acs_url": "javascript:alert(1)"},
		errs.CodeSAMLCertificateInvalid: {"certificate": "not a certificate"},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, change); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("update with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), code)
		}
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{"name": "Wiki", "status": "active", "acs_url": " https://wiki.example.test/acs "})
	var updated ServiceProvider
	dbtest.Decode(t, rec, &updated)
	if rec.Code != http.StatusOK || updated.Name != "Wiki" || updated.Status != "active" || updated.ACSURL != "https://wiki.example.test/acs" {
		t.Errorf("update: %d %s", rec.Code, rec.Body.String())
	}

	otherPath := "/tenants/" + other.String() + "/saml-providers/" + sp.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]any{"acs_url": "https://evil.example.test/acs"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organisation %s on the SP: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodGet, base, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organisation listing this organisation's SPs: %d, want 403", rec.Code)
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if rec := dbtest.Do(t, asAdmin, method, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s a deleted SP: %d, want 404", method, rec.Code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND resource_id = $2 AND action LIKE 'saml.sp_%' AND actor_user_id = $3`, tenant, sp.ID, admin.ID); n != 3 {
		t.Errorf("%d SP changes recorded, want created, updated and deleted", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_service_providers WHERE tenant_id = $1 AND acs_url = 'https://sp.example.test/acs'`, other); n != 1 {
		t.Errorf("another organisation's SP: %d, want its one untouched", n)
	}
}

// TestSAMLRegistryRefusesBadInputAsInvalid checks that an unknown status on
// create, or a second SP with an entity ID the organisation already serves, is
// refused as the client's mistake.
func TestSAMLRegistryRefusesBadInputAsInvalid(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(dbtest.Pool(t), keyPEM, certPEM, "https://login.id.qeet.in", sessionsByCookie{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: NewService(dbtest.Pool(t), nil, testAppBase), IdP: idp}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	cert, _ := selfSignedCert(t)
	connection := map[string]any{"name": "Okta", "idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso", "idp_certificate": cert, "status": "enabled"}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/tenants/"+tenant.String()+"/saml", connection); !strings.Contains(rec.Body.String(), errs.CodeSAMLStatusInvalid) {
		t.Errorf("a connection with an unknown status: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLStatusInvalid)
	}
	providers := "/tenants/" + tenant.String() + "/saml-providers"
	provider := map[string]any{"name": "App", "entity_id": "https://sp.example.test", "acs_url": "https://sp.example.test/acs", "status": "enabled"}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, providers, provider); !strings.Contains(rec.Body.String(), errs.CodeSAMLStatusInvalid) {
		t.Errorf("an SP with an unknown status: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLStatusInvalid)
	}
	provider["status"] = "active"
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, providers, provider); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, providers, provider); rec.Code/100 != 4 {
		t.Errorf("a second SP with the same entity ID: %d %s, want a 4xx", rec.Code, rec.Body.String())
	}
}
