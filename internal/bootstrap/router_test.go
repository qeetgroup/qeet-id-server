package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// pathParam is one {param} or trailing * of a route pattern.
var pathParam = regexp.MustCompile(`\{[^}]+\}|\*$`)

// TestEncodedSlashIsRefused checks that every mounted route with a path
// parameter answers 400 when the parameter carries an encoded slash or
// backslash, before any policy is looked up: the router splits the raw path
// and the permission, step-up, row-level scoping, CSRF and idempotency checks
// the decoded one, so such a path could mean one route to the router and
// another to a check.
func TestEncodedSlashIsRefused(t *testing.T) {
	router := NewRouter(routeInventoryDeps(t))
	checked := 0
	for route := range productionRouteInventory(t) {
		method, pattern, _ := strings.Cut(route, " ")
		if !pathParam.MatchString(pattern) {
			continue
		}
		for _, separator := range []string{"%2F", "%2f", "%5C", "%5c"} {
			path := pathParam.ReplaceAllString(pattern, "a"+separator+"b")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errs.CodeBadRequest) {
				t.Errorf("%s %s: %d %.120s, want 400 %s", method, path, rec.Code, rec.Body.String(), errs.CodeBadRequest)
			}
		}
		checked++
	}
	if checked < 100 {
		t.Fatalf("checked %d routes with a path parameter, want the router's hundreds", checked)
	}
}

// TestOneTokenEndpoint checks that the token endpoint is one route, mounted
// alone in the machine-traffic rate-limit group and never in the sign-in one,
// uncacheable, CSRF-exempt and open to the applications' browser origins, and
// that the paths it replaced are gone from the router and from every list.
func TestOneTokenEndpoint(t *testing.T) {
	const route, path = "POST /v1/oauth/token", "/v1/oauth/token"
	deps := routeInventoryDeps(t)
	group := func(mount func(chi.Router, Deps)) map[string]routeClass {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) { mount(r, deps) })
		return walkRoutes(t, r)
	}
	if got := group(mountV1TokenRoutes); len(got) != 1 || got[route] != (routeClass{}) {
		t.Errorf("the token group mounts %v, want only %s", got, route)
	}
	if _, ok := group(mountV1PublicRoutes)[route]; ok {
		t.Errorf("%s is in the sign-in rate-limit group", route)
	}
	if !slices.Contains(NoStoreRoutes(), route) || !slices.Contains(csrfExemptPaths(), path) || !slices.Contains(browserAppPaths, path) {
		t.Errorf("%s is missing from the no-store, CSRF-exempt or browser-application list", route)
	}
	mounted := productionRouteInventory(t)
	for _, gone := range []string{"/v1/oauth/token-code", "/v1/agents/token"} {
		if _, ok := mounted[http.MethodPost+" "+gone]; ok {
			t.Errorf("%s is still mounted", gone)
		}
		if slices.Contains(NoStoreRoutes(), http.MethodPost+" "+gone) || slices.Contains(csrfExemptPaths(), gone) || slices.Contains(browserAppPaths, gone) {
			t.Errorf("%s is still listed", gone)
		}
	}
}
