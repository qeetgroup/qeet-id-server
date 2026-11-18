package saml

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestConnectionWritesRejectInvalidSSOURL checks that creating or updating a
// connection refuses an SSO URL that isn't an absolute https URL.
func TestConnectionWritesRejectInvalidSSOURL(t *testing.T) {
	pemStr, _ := selfSignedCert(t)
	organization := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	user := uuid.New()
	principal := &httpx.Principal{UserID: &user, OrganizationID: &organization, ActorType: "user", Subject: user.String()}
	router := chi.NewRouter()
	(&Handler{Service: &Service{}}).Mount(router)

	send := func(method, path string, body map[string]any) *httptest.ResponseRecorder {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(httpx.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	base := "/organizations/" + organization.String() + "/saml"
	for _, sso := range []string{"http://idp.example.com/sso", "https://user@idp.example.com/sso", "idp.example.com/sso"} {
		create := send(http.MethodPost, base, map[string]any{
			"name": "IdP", "idp_entity_id": "https://idp.example.com", "idp_sso_url": sso, "idp_certificate": pemStr,
		})
		if create.Code != http.StatusUnprocessableEntity || !strings.Contains(create.Body.String(), CodeSSOURLInvalid) {
			t.Errorf("create with %q = %d %s, want 422 %s", sso, create.Code, create.Body.String(), CodeSSOURLInvalid)
		}
		update := send(http.MethodPatch, base+"/"+uuid.NewString(), map[string]any{"idp_sso_url": sso})
		if update.Code != http.StatusUnprocessableEntity || !strings.Contains(update.Body.String(), CodeSSOURLInvalid) {
			t.Errorf("update with %q = %d %s, want 422 %s", sso, update.Code, update.Body.String(), CodeSSOURLInvalid)
		}
	}
}
