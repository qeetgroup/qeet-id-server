//go:build integration

package saml

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestCreateSPPlanGateWithOneConnection checks, with only one connection free,
// that registering a service provider asks the plan first: a plan with SSO
// registers it, one without is refused, and invalid input is refused as
// invalid before the plan is asked.
func TestCreateSPPlanGateWithOneConnection(t *testing.T) {
	pool := dbtest.Pool(t)
	paid, free := dbtest.Organization(t), dbtest.Organization(t)
	keyPEM, certPEM, err := GenerateIdPKeyPEM("Test Qeet IdP")
	if err != nil {
		t.Fatal(err)
	}
	idp, err := NewIdP(pool, keyPEM, certPEM, "https://login.id.qeet.in", sessionsByCookie{})
	if err != nil {
		t.Fatal(err)
	}
	idp.SetPlanGate(poolGate{pool: pool, allowed: map[uuid.UUID]bool{paid: true}})
	admins := map[uuid.UUID]uuid.UUID{paid: dbtest.User(t, paid, paid).ID, free: dbtest.User(t, free, free).ID}
	create := func(organization uuid.UUID, acs string) *httptest.ResponseRecorder {
		h := dbtest.Serve(dbtest.Principal(admins[organization], organization), (&Handler{Service: &Service{}, IdP: idp}).Mount)
		return dbtest.Do(t, h, http.MethodPost, "/organizations/"+organization.String()+"/saml-providers",
			map[string]any{"name": "App", "entity_id": "https://sp.example.com", "acs_url": acs})
	}

	dbtest.LeaveOneConnection(t)
	if rec := create(paid, "https://sp.example.com/acs"); rec.Code != http.StatusCreated {
		t.Errorf("SP in a plan with SSO = %d %s, want 201", rec.Code, rec.Body.String())
	}
	if rec := create(free, "https://sp.example.com/acs"); rec.Code != http.StatusPaymentRequired {
		t.Errorf("SP in a plan without SSO = %d %s, want 402", rec.Code, rec.Body.String())
	}
	if rec := create(free, "http://sp.example.com/acs"); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), CodeACSURLInvalid) {
		t.Errorf("invalid SP in a plan without SSO = %d %s, want %s", rec.Code, rec.Body.String(), CodeACSURLInvalid)
	}
}
