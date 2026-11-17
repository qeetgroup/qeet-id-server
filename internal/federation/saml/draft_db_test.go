//go:build integration

package saml

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAConnectionIsNamedBeforeItsIdP checks that a connection can be created
// with a name alone, as a draft whose addresses and metadata go to the IdP
// first, and that it is turned on only once the IdP's details are added.
func TestAConnectionIsNamedBeforeItsIdP(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := &Handler{Service: NewService(dbtest.Pool(t), nil, testAppBase), PublicBaseURL: testPublicBase}
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	public := chi.NewRouter()
	h.MountPublic(public)
	base := "/tenants/" + organization.String() + "/saml"

	if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": "Okta", "status": "active"}); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionIncomplete) {
		t.Errorf("create an active connection with no IdP: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionIncomplete)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": "Okta", "idp_entity_id": "https://idp.example.test"}); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionFieldsRequired) {
		t.Errorf("create with only some of the IdP's details: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionFieldsRequired)
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, map[string]any{"name": " Okta "})
	var draft struct {
		Connection
		SPAddresses
	}
	dbtest.Decode(t, rec, &draft)
	if rec.Code != http.StatusCreated || draft.Name != "Okta" || draft.Status != "draft" || len(draft.Certificates) != 0 ||
		draft.ACSURL != acsURL(testPublicBase, draft.ID) || draft.EntityID != spEntityID(testPublicBase, draft.ID) || draft.SPAddresses.MetadataURL == "" {
		t.Fatalf("create with a name alone: %d %s; want a draft with its addresses", rec.Code, rec.Body.String())
	}
	if meta := dbtest.Do(t, public, http.MethodGet, "/saml/metadata/"+draft.ID.String(), nil); meta.Code != http.StatusOK || !strings.Contains(meta.Body.String(), draft.ACSURL) {
		t.Errorf("the draft's metadata: %d %s", meta.Code, meta.Body.String())
	}

	path := base + "/" + draft.ID.String()
	active := map[string]any{"status": "active"}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, active); !strings.Contains(rec.Body.String(), errs.CodeSAMLConnectionIncomplete) {
		t.Errorf("turn on the draft with no IdP: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeSAMLConnectionIncomplete)
	}
	cert, _ := selfSignedCert(t)
	details := map[string]any{"idp_entity_id": "https://idp.example.test", "idp_sso_url": "https://idp.example.test/sso", "idp_certificate": cert}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, path, details); rec.Code != http.StatusOK {
		t.Fatalf("add the IdP's details: %d %s", rec.Code, rec.Body.String())
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, active)
	var on Connection
	dbtest.Decode(t, rec, &on)
	if rec.Code != http.StatusOK || on.Status != "active" || len(on.Certificates) != 1 {
		t.Errorf("turn on the completed connection: %d %s", rec.Code, rec.Body.String())
	}
}
