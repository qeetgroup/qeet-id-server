//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
)

// TestHandingOutAuthorityNeedsAStepUp: step-up made a session prove a factor
// again before sensitive actions, but not before the ones that hand out
// authority or move an account's recovery address, so a stolen administrator
// token could grant the owner role, attach permissions to a role, invite an
// accomplice as owner, or point the account's email at the attacker. Those now
// need a step-up from the session (the email change, from anyone holding a
// factor), and pass once it has one.
func TestHandingOutAuthorityNeedsAStepUp(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	authSvc, _ := newAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("authority"))
	routes := []struct{ method, pattern, path string }{
		{http.MethodPost, "/users/{userID}/tenants/{tenantID}/roles/{roleID}", "/v1/users/" + uuid.NewString() + "/tenants/" + tenantID.String() + "/roles/" + uuid.NewString()},
		{http.MethodPost, "/roles/{roleID}/permissions/{permID}", "/v1/roles/" + uuid.NewString() + "/permissions/" + uuid.NewString()},
		{http.MethodPost, "/invites", "/v1/invites"},
		{http.MethodPost, "/me/email/change/start", "/v1/me/email/change/start"},
	}
	api := func(userID, sessionID uuid.UUID) http.Handler {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) {
			r.Use(withSessionPrincipal(userID, tenantID, sessionID))
			r.Use(svc.StepUpGate(bootstrap.StepUpRoutes()))
			for _, rt := range routes {
				r.MethodFunc(rt.method, rt.pattern, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			}
		})
		return r
	}
	call := func(h http.Handler, method, path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		return rr
	}

	admin := createUserInTenant(t, ctx, tenantID)
	holdApp(t, ctx, svc, admin)
	pair, err := authSvc.IssuePair(ctx, admin, tenantID, "203.0.113.60", "browser", "password")
	if err != nil {
		t.Fatal(err)
	}
	h := api(admin, pair.SessionID)
	for _, rt := range routes {
		if rr := call(h, rt.method, rt.path); rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "step_up_required") {
			t.Fatalf("%s %s without a step-up = %d %s, want 403 step_up_required", rt.method, rt.pattern, rr.Code, rr.Body)
		}
	}
	recordStepUp(t, ctx, svc, admin, pair.SessionID, "totp")
	for _, rt := range routes {
		if rr := call(h, rt.method, rt.path); rr.Code != http.StatusOK {
			t.Fatalf("%s %s after a step-up = %d %s, want 200", rt.method, rt.pattern, rr.Code, rr.Body)
		}
	}

	// Moving one's own address needs a step-up only from someone holding a
	// factor: there is nothing else to step up with.
	newcomer := createUserInTenant(t, ctx, tenantID)
	own, err := authSvc.IssuePair(ctx, newcomer, tenantID, "203.0.113.61", "browser", "password")
	if err != nil {
		t.Fatal(err)
	}
	if rr := call(api(newcomer, own.SessionID), http.MethodPost, "/v1/me/email/change/start"); rr.Code != http.StatusOK {
		t.Fatalf("email change by someone with no factor = %d %s, want 200", rr.Code, rr.Body)
	}
}
