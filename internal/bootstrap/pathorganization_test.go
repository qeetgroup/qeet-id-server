package bootstrap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestOrganizationHandlersCheckThePath checks that the handlers which read the
// organization from a {organizationID} path refuse another organization's path
// themselves, without EnforceOrganizationScope in front of them, before any
// work: their services here are empty, so one that goes on fails the test.
func TestOrganizationHandlersCheckThePath(t *testing.T) {
	deps := routeInventoryDeps(t)
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) { mountAuthenticatedRoutes(r, deps) })
	own, other, user := uuid.New(), uuid.New(), uuid.New()
	id := uuid.NewString()
	for _, route := range []string{
		"GET /v1/organizations/{other}",
		"PATCH /v1/organizations/{other}",
		"DELETE /v1/organizations/{other}",
		"POST /v1/organizations/{other}/deletion/cancel",
		"GET /v1/organizations/{other}/branding",
		"PUT /v1/organizations/{other}/branding",
		"GET /v1/organizations/{other}/policy",
		"PUT /v1/organizations/{other}/policy",
		"PATCH /v1/organizations/{other}/policy",
		"GET /v1/organizations/{other}/service-principals",
		"GET /v1/organizations/{other}/api-keys",
		"POST /v1/organizations/{other}/api-keys/{id}/rotate",
		"GET /v1/organizations/{other}/gdpr/purge",
		"GET /v1/organizations/{other}/gdpr/export",
		"GET /v1/organizations/{other}/gdpr/export/{id}",
		"GET /v1/organizations/{other}/compliance/audits",
		"GET /v1/organizations/{other}/webhooks",
		"GET /v1/organizations/{other}/webhooks/events",
		"GET /v1/organizations/{other}/groups",
		"GET /v1/organizations/{other}/social/providers",
		"GET /v1/organizations/{other}/analytics/overview",
		"GET /v1/organizations/{other}/security/risk-settings",
		"GET /v1/organizations/{other}/rate-limits",
		"POST /v1/organizations/{other}/access/v1/evaluation",
		"GET /v1/organizations/{other}/audit",
		"GET /v1/organizations/{other}/audit/anomaly-settings",
		"GET /v1/organizations/{other}/service-health",
		"GET /v1/organizations/{other}/saml",
		"GET /v1/organizations/{other}/scim/tokens",
		"GET /v1/organizations/{other}/admin-portal/links",
		"GET /v1/organizations/{other}/oidc/clients",
		"GET /v1/organizations/{other}/agents",
		"GET /v1/organizations/{other}/auth-hooks",
		"GET /v1/organizations/{other}/billing/subscription",
		"GET /v1/organizations/{other}/email-templates",
		"GET /v1/organizations/{other}/log-sinks",
		"GET /v1/organizations/{other}/retention",
	} {
		method, path, _ := strings.Cut(route, " ")
		path = strings.NewReplacer("{other}", other.String(), "{id}", id).Replace(path)
		t.Run(route, func(t *testing.T) {
			r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
			r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", UserID: &user, OrganizationID: &own}))
			rec := httptest.NewRecorder()
			if err := serveRecovering(router, rec, r); err != nil {
				t.Fatalf("the handler went on with another organization's path: %v", err)
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status %d %s, want 403", rec.Code, rec.Body.String())
			}
		})
	}
}

// serveRecovering serves r, turning a panic into an error.
func serveRecovering(h http.Handler, w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	h.ServeHTTP(w, r)
	return nil
}
