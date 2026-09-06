package bootstrap

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"gopkg.in/yaml.v3"
)

var openAPIMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace,
}

type openAPIOperation struct {
	Security []map[string][]string `yaml:"security"`
}

type openAPIPathItem struct {
	Get     *openAPIOperation `yaml:"get"`
	Head    *openAPIOperation `yaml:"head"`
	Post    *openAPIOperation `yaml:"post"`
	Put     *openAPIOperation `yaml:"put"`
	Patch   *openAPIOperation `yaml:"patch"`
	Delete  *openAPIOperation `yaml:"delete"`
	Options *openAPIOperation `yaml:"options"`
	Trace   *openAPIOperation `yaml:"trace"`
}

func (p openAPIPathItem) operations() map[string]*openAPIOperation {
	return map[string]*openAPIOperation{
		http.MethodGet: p.Get, http.MethodHead: p.Head, http.MethodPost: p.Post,
		http.MethodPut: p.Put, http.MethodPatch: p.Patch,
		http.MethodDelete: p.Delete, http.MethodOptions: p.Options,
		http.MethodTrace: p.Trace,
	}
}

type openAPIDocument struct {
	Info struct {
		Description string `yaml:"description"`
	} `yaml:"info"`
	Servers []struct {
		URL string `yaml:"url"`
	} `yaml:"servers"`
	Paths map[string]openAPIPathItem `yaml:"paths"`
}

type routeClass struct {
	authenticated bool
}

type contractDiff struct {
	undocumented []string
	stale        []string
	security     []string
}

func compareRouteContract(mounted map[string]routeClass, documented map[string]*openAPIOperation) contractDiff {
	var diff contractDiff
	for key, class := range mounted {
		operation, ok := documented[key]
		if !ok {
			diff.undocumented = append(diff.undocumented, key)
			continue
		}
		hasBearer := operationHasSecurity(operation, "bearerAuth")
		hasAPIKey := operationHasSecurity(operation, "apiKeyAuth")
		if class.authenticated && (!hasBearer || !hasAPIKey) {
			diff.security = append(diff.security, key+" must declare bearerAuth and apiKeyAuth")
		}
		if !class.authenticated && (hasBearer || hasAPIKey) {
			diff.security = append(diff.security, key+" is outside API auth but declares bearerAuth/apiKeyAuth")
		}
	}
	for key := range documented {
		if _, ok := mounted[key]; !ok {
			diff.stale = append(diff.stale, key)
		}
	}
	sort.Strings(diff.undocumented)
	sort.Strings(diff.stale)
	sort.Strings(diff.security)
	return diff
}

func operationHasSecurity(operation *openAPIOperation, scheme string) bool {
	if operation == nil {
		return false
	}
	for _, requirement := range operation.Security {
		if _, ok := requirement[scheme]; ok {
			return true
		}
	}
	return false
}

func loadOpenAPIOperations(t *testing.T) map[string]*openAPIOperation {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate OpenAPI coverage test")
	}
	dir := filepath.Join(filepath.Dir(source), "..", "..", "api", "openapi")
	documented := map[string]*openAPIOperation{}
	for _, name := range []string{"auth.yaml", "management.yaml", "federation.yaml", "developer.yaml", "operations.yaml"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var document openAPIDocument
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for path, item := range document.Paths {
			for method, operation := range item.operations() {
				if operation == nil {
					continue
				}
				key := method + " " + normalizeContractPath(path)
				if _, exists := documented[key]; exists {
					t.Fatalf("duplicate OpenAPI operation %s (including %s)", key, name)
				}
				documented[key] = operation
			}
		}
	}
	return documented
}

func normalizeContractPath(path string) string {
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func walkRoutes(t *testing.T, router chi.Routes) map[string]routeClass {
	t.Helper()
	routes := map[string]routeClass{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes[method+" "+normalizeContractPath(route)] = routeClass{}
		return nil
	}); err != nil {
		t.Fatalf("walk production routes: %v", err)
	}
	return routes
}

func productionRouteInventory(t *testing.T) map[string]routeClass {
	t.Helper()
	deps := routeInventoryDeps(t)
	all := chi.NewRouter()
	// Limiters are irrelevant to the route inventory (Group composes middleware
	// without changing patterns); pass real ones so the production call shape is
	// exercised rather than a divergent test-only path.
	mountRootPublicRoutes(all, deps, ratelimit.New(5, 20), ratelimit.New(50, 200))
	all.Route("/v1", func(r chi.Router) {
		mountV1PublicRoutes(r, deps)
		mountAuthenticatedRoutes(r, deps)
	})
	mounted := walkRoutes(t, all)

	authenticatedRouter := chi.NewRouter()
	authenticatedRouter.Route("/v1", func(r chi.Router) { mountAuthenticatedRoutes(r, deps) })
	for key := range walkRoutes(t, authenticatedRouter) {
		mounted[key] = routeClass{authenticated: true}
	}
	return mounted
}

func TestProductionRoutesMatchOpenAPI(t *testing.T) {
	diff := compareRouteContract(productionRouteInventory(t), loadOpenAPIOperations(t))
	if len(diff.undocumented) > 0 || len(diff.stale) > 0 || len(diff.security) > 0 {
		t.Fatalf("router/OpenAPI mismatch\nundocumented mounted routes: %v\nstale documented operations: %v\nsecurity mismatches: %v",
			diff.undocumented, diff.stale, diff.security)
	}
}

func TestRouteContractComparisonDetectsDrift(t *testing.T) {
	documented := map[string]*openAPIOperation{
		"GET /known": {Security: []map[string][]string{{"bearerAuth": {}}, {"apiKeyAuth": {}}}},
		"GET /stale": {Security: []map[string][]string{}},
	}
	mounted := map[string]routeClass{
		"GET /known": {authenticated: true},
		"GET /rogue": {authenticated: true},
	}
	diff := compareRouteContract(mounted, documented)
	if fmt.Sprint(diff.undocumented) != "[GET /rogue]" {
		t.Fatalf("undocumented detection = %v", diff.undocumented)
	}
	if fmt.Sprint(diff.stale) != "[GET /stale]" {
		t.Fatalf("stale detection = %v", diff.stale)
	}

	documented["GET /known"] = &openAPIOperation{Security: []map[string][]string{}}
	diff = compareRouteContract(map[string]routeClass{"GET /known": {authenticated: true}}, documented)
	if len(diff.security) != 1 {
		t.Fatalf("security mismatch detection = %v", diff.security)
	}
}

func TestOpenAPIMethodInventoryIsStable(t *testing.T) {
	if len(openAPIMethods) != 8 {
		t.Fatalf("HTTP operation inventory unexpectedly changed: %v", openAPIMethods)
	}
}

func TestOpenAPIMetadataReferencesLiveProductionSurface(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate metadata test")
	}
	repoRoot := filepath.Join(filepath.Dir(source), "..", "..")
	for _, path := range []string{
		"internal/bootstrap/router.go",
		"internal/bootstrap/openapi_coverage_test.go",
	} {
		if _, err := os.Stat(filepath.Join(repoRoot, path)); err != nil {
			t.Fatalf("documented source path %s does not exist: %v", path, err)
		}
	}
	for _, name := range []string{"auth.yaml", "management.yaml", "federation.yaml", "developer.yaml", "operations.yaml"} {
		raw, err := os.ReadFile(filepath.Join(repoRoot, "api", "openapi", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var document openAPIDocument
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if !strings.Contains(document.Info.Description, "internal/bootstrap/router.go") ||
			!strings.Contains(document.Info.Description, "internal/bootstrap/openapi_coverage_test.go") {
			t.Errorf("%s description does not reference the live router and coverage test", name)
		}
		hasProduction := false
		for _, server := range document.Servers {
			if server.URL == "https://api.id.qeet.in" {
				hasProduction = true
			}
			if server.URL == "http://localhost:4000" {
				t.Errorf("%s retains the obsolete localhost:4000 server", name)
			}
		}
		if !hasProduction {
			t.Errorf("%s does not declare https://api.id.qeet.in", name)
		}
	}
}
