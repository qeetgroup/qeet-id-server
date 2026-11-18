//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestSAMLServiceProvidersOverHTTP checks that an organization registers,
// lists, reads, changes and deletes the service providers its IdP serves,
// refusing invalid input and auditing each change, and that another
// organization can neither see nor change them.
func TestSAMLServiceProvidersOverHTTP(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin, otherAdmin := dbtest.User(t, organization, organization), dbtest.User(t, other, other)
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(dbtest.Pool(t), keyPEM, certPEM, "https://login.id.qeet.in", sessionsByCookie{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: &Service{}, IdP: idp}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	base := "/organizations/" + organization.String() + "/saml-providers"
	spCert, _ := selfSignedCert(t)
	provider := map[string]any{"name": " App ", "entity_id": " https://sp.example.test ", "acs_url": "https://sp.example.test/acs",
		"certificate": spCert, "require_signed_requests": true}

	for code, change := range map[string]map[string]any{
		CodeSPFieldsRequired:   {"entity_id": " "},
		CodeACSURLInvalid:      {"acs_url": "http://sp.example.test/acs"},
		CodeCertificateInvalid: {"certificate": "not a certificate"},
		CodeCertificateUnused:  {"require_signed_requests": false},
	} {
		if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, withChanges(provider, change)); rec.Code/100 != 4 || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("register with %v: %d %s, want %s", change, rec.Code, rec.Body.String(), code)
		}
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, provider)
	var sp ServiceProvider
	dbtest.Decode(t, rec, &sp)
	if rec.Code != http.StatusCreated || sp.Name != "App" || sp.EntityID != "https://sp.example.test" || sp.Status != "draft" ||
		sp.NameIDFormat != nameIDEmail || sp.NameIDAttribute != "email" || sp.OrganizationID != organization {
		t.Fatalf("register: %d %s; want a trimmed draft with the email NameID defaults", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/organizations/"+other.String()+"/saml-providers", provider); rec.Code != http.StatusCreated {
		t.Fatalf("another organization registering the same entity: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil)); len(ids) != 1 || ids[0] != sp.ID {
		t.Errorf("list %v, want only the organization's own %s", ids, sp.ID)
	}
	path := base + "/" + sp.ID.String()
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), sp.ID.String()) {
		t.Errorf("get: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, base+"/not-a-uuid", nil); !strings.Contains(rec.Body.String(), CodeIDInvalid) {
		t.Errorf("get with a malformed ID: %d %s, want %s", rec.Code, rec.Body.String(), CodeIDInvalid)
	}
	for code, change := range map[string]map[string]any{
		CodeStatusInvalid:      {"status": "retired"},
		CodeACSURLInvalid:      {"acs_url": "javascript:alert(1)"},
		CodeCertificateInvalid: {"certificate": "not a certificate"},
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

	otherPath := "/organizations/" + other.String() + "/saml-providers/" + sp.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]any{"acs_url": "https://evil.example.test/acs"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organization %s on the SP: %d, want 404", method, rec.Code)
		}
	}
	if rec := dbtest.Do(t, asOther, http.MethodGet, base, nil); rec.Code != http.StatusForbidden {
		t.Errorf("another organization listing this organization's SPs: %d, want 403", rec.Code)
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if rec := dbtest.Do(t, asAdmin, method, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s a deleted SP: %d, want 404", method, rec.Code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2 AND action LIKE 'saml.sp_%' AND actor_user_id = $3`, organization, sp.ID, admin.ID); n != 3 {
		t.Errorf("%d SP changes recorded, want created, updated and deleted", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.saml_service_providers WHERE organization_id = $1 AND acs_url = 'https://sp.example.test/acs'`, other); n != 1 {
		t.Errorf("another organization's SP: %d, want its one untouched", n)
	}
}
