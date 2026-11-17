package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

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
