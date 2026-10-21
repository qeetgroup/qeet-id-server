package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type allowRouteInventoryChecker struct{}

func (allowRouteInventoryChecker) Check(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return true, nil
}

func routeInventoryDeps(t *testing.T) Deps {
	t.Helper()
	var deps Deps
	value := reflect.ValueOf(&deps).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.CanSet() && field.Kind() == reflect.Pointer && field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
	}
	deps.RBACChecker = allowRouteInventoryChecker{}

	// These handlers conditionally mount route families when an optional
	// collaborator is present. Populate those exported pointers so the inventory
	// includes the same feature-complete surface as production.
	for _, pair := range [][2]string{{"SAML", "IdP"}, {"GDPR", "Evidence"}} {
		outer := value.FieldByName(pair[0])
		if !outer.IsValid() || outer.IsNil() {
			t.Fatalf("missing handler field %s", pair[0])
		}
		inner := outer.Elem().FieldByName(pair[1])
		if !inner.IsValid() || !inner.CanSet() || inner.Kind() != reflect.Pointer {
			t.Fatalf("missing optional dependency %s.%s", pair[0], pair[1])
		}
		inner.Set(reflect.New(inner.Type().Elem()))
	}
	return deps
}

func TestDirectoryConnectionsRequireConnectionRead(test *testing.T) {
	permission := userPermissionMap()["GET /v1/tenants/{tenantID}/directory/connections"]
	if permission != "connection.read" {
		test.Fatalf("directory inventory permission = %q, want connection.read", permission)
	}
}

func TestAuthenticatedRoutesHaveExplicitPolicies(t *testing.T) {
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		mountAuthenticatedRoutes(r, routeInventoryDeps(t))
	})

	mounted := map[string]struct{}{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+route] = struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("walk authenticated router: %v", err)
	}

	policies := RoutePolicies()
	var missing, stale []string
	for route := range mounted {
		if _, ok := policies[route]; !ok {
			missing = append(missing, route)
		}
	}
	for route := range policies {
		if _, ok := mounted[route]; !ok {
			stale = append(stale, route)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("route policy mismatch\nmissing policies: %v\nstale policies: %v", missing, stale)
	}
}

// TestEveryRouteNamesAnApplicationScope fails when an authenticated route's
// policy names no scope for an application's token: without one, opening the
// route to applications would let any of them act there with the user's whole
// role set. Administrative routes need their permission as the scope, and the
// routes open to applications need one too.
func TestEveryRouteNamesAnApplicationScope(t *testing.T) {
	policies := RoutePolicies()
	var unscoped, mismatched []string
	for route, p := range policies {
		switch {
		case p.ApplicationScope == "":
			unscoped = append(unscoped, route)
		case p.UserPermission != "" && p.ApplicationScope != p.UserPermission:
			mismatched = append(mismatched, route+" ("+p.ApplicationScope+" for "+p.UserPermission+")")
		}
	}
	sort.Strings(unscoped)
	sort.Strings(mismatched)
	if len(unscoped) > 0 || len(mismatched) > 0 {
		t.Fatalf("routes with no application scope: %v\nscope differs from permission: %v", unscoped, mismatched)
	}
	for _, route := range ApplicationTokenRoutes() {
		if got := policies[route].ApplicationScope; got != "openid" {
			t.Errorf("%s needs %q of an application, want openid", route, got)
		}
	}
	for route, want := range map[string]string{
		"GET /v1/me":              "account.read",
		"PATCH /v1/me":            "account.write",
		"POST /v1/account/delete": "account.write",
		"GET /v1/users":           "user.read",
		"DELETE /v1/users/{id}":   "user.write",
	} {
		if got := policies[route].ApplicationScope; got != want {
			t.Errorf("%s needs %q of an application, want %q", route, got, want)
		}
	}
}

// TestNoAuthenticatedRouteIsCSRFExempt is the guard for the exemption class of
// bug: a CSRF exemption written as a prefix over a public feature area also
// covers any authenticated mutation later mounted underneath it. Two such
// routes existed — POST /v1/social/providers under "/v1/social/", and
// POST /v1/oauth/bc-authorize/decision under "/v1/oauth/bc-authorize".
//
// Every route in the authenticated tree is reachable with a cookie session, so
// none of them may be exempt.
func TestNoAuthenticatedRouteIsCSRFExempt(t *testing.T) {
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		mountAuthenticatedRoutes(r, routeInventoryDeps(t))
	})

	exempt := csrfExemptPaths()
	var offenders []string
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return nil // read-only methods never reach the CSRF check
		}
		// chi hands back the pattern; substitute a plausible value for each
		// parameter so the exemption matcher sees a concrete path.
		concrete := routeParamPattern.ReplaceAllString(route, "00000000-0000-0000-0000-000000000000")
		for _, pattern := range exempt {
			if httpx.MatchExemptPathForTest(pattern, concrete) {
				offenders = append(offenders, method+" "+route+"  (exempted by "+pattern+")")
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk authenticated router: %v", err)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("authenticated mutation routes are CSRF-exempt:\n  %s", strings.Join(offenders, "\n  "))
	}
}

var routeParamPattern = regexp.MustCompile(`\{[^}]+\}`)

// TestLoginSessionRoutesStayNarrow guards the routes that accept the hosted
// login's session cookie in place of a bearer token: exactly the passkey list,
// rename and enrolment routes, each mounted in the authenticated tree, open to
// users only, and CSRF-checked. Removing a passkey stays token-only.
func TestLoginSessionRoutesStayNarrow(t *testing.T) {
	want := []string{
		"GET /v1/auth/me",
		"GET /v1/me",
		"GET /v1/me/organizations",
		"GET /v1/passkeys",
		"PATCH /v1/passkeys/{id}",
		"POST /v1/passkeys/register/begin",
		"POST /v1/passkeys/register/finish",
	}
	got := LoginSessionRoutes()
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(sorted, want) {
		t.Fatalf("hosted-login session routes = %v, want %v", sorted, want)
	}

	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		mountAuthenticatedRoutes(r, routeInventoryDeps(t))
	})
	mounted := map[string]struct{}{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+route] = struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("walk authenticated router: %v", err)
	}
	policies := RoutePolicies()
	for _, route := range got {
		if _, ok := mounted[route]; !ok {
			t.Errorf("%s is not an authenticated route", route)
		}
		if p := policies[route]; !p.AllowUser || p.AllowAPIKey || p.AllowService || p.AllowAgent || p.UserPermission != "" || p.HandlerAuthorizedMachine {
			t.Errorf("%s policy = %+v, want user-only", route, policies[route])
		}
		method, path, _ := strings.Cut(route, " ")
		concrete := routeParamPattern.ReplaceAllString(path, "00000000-0000-0000-0000-000000000000")
		for _, pattern := range csrfExemptPaths() {
			if method != http.MethodGet && httpx.MatchExemptPathForTest(pattern, concrete) {
				t.Errorf("%s is CSRF-exempt (by %s)", route, pattern)
			}
		}
	}
}

// TestApplicationTokenRoutesStayNarrow pins the authenticated routes that
// accept a token issued to an application: only the endpoint returning the
// signed-in user's own claims. Every one must be a mounted authenticated route.
func TestApplicationTokenRoutesStayNarrow(t *testing.T) {
	want := []string{"GET /v1/oauth/userinfo", "POST /v1/oauth/userinfo"}
	got := ApplicationTokenRoutes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("application-token routes = %v, want %v", got, want)
	}
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		mountAuthenticatedRoutes(r, routeInventoryDeps(t))
	})
	mounted := map[string]struct{}{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+route] = struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("walk authenticated router: %v", err)
	}
	for _, route := range got {
		if _, ok := mounted[route]; !ok {
			t.Errorf("%s is not an authenticated route", route)
		}
	}
}

// sensitiveLooking matches the paths of routes that change factors, machine
// credentials, secrets, sign-in or security policy, single sign-on, retention
// or audit streaming, or destroy an account or organisation.
var sensitiveLooking = regexp.MustCompile(`/mfa/|/passkeys|/api-keys|/service-principals|/agents|` +
	`/oidc/clients|/scim/token|/credentials|/webhooks|/auth-hooks|/secrets|/vault/tokens|/provider-config|` +
	`/policy$|/auth-policy|/risk-settings|/bots/settings|/ip-rules|/rate-limits|/mfa-required|/mfa$|` +
	`/password$|/saml|/ldap|/social/|/domains|/mappings|/admin-portal|/email-templates|/retention|` +
	`/anomaly-settings|/log-sinks|/purge|/account/|/sessions|/gdpr/|/oauth/(grants|devices)|/anomalies/|` +
	`^/v1/tenants/\{tenantID\}$|^/v1/users/\{id\}$`)

// TestSensitiveRoutesNeedStepUp fails when a mutating route that looks
// sensitive is neither in the step-up catalogue nor exempted with a reason, and
// when either list names a route that is not mounted.
func TestSensitiveRoutesNeedStepUp(t *testing.T) {
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		mountAuthenticatedRoutes(r, routeInventoryDeps(t))
	})
	mounted := map[string]bool{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	}); err != nil {
		t.Fatalf("walk authenticated router: %v", err)
	}
	gated, exempt := stepUpRoutes(), stepUpExempt()
	var unclassified, stale, both []string
	for route := range mounted {
		method, path, _ := strings.Cut(route, " ")
		if method == http.MethodGet || method == http.MethodHead || !sensitiveLooking.MatchString(path) {
			continue
		}
		if _, ok := gated[route]; ok {
			continue
		}
		if _, ok := exempt[route]; !ok {
			unclassified = append(unclassified, route)
		}
	}
	for route := range gated {
		if !mounted[route] {
			stale = append(stale, route)
		}
		if _, ok := exempt[route]; ok {
			both = append(both, route)
		}
	}
	for route := range exempt {
		if !mounted[route] {
			stale = append(stale, route)
		}
	}
	sort.Strings(unclassified)
	sort.Strings(stale)
	sort.Strings(both)
	if len(unclassified) > 0 {
		t.Errorf("sensitive-looking routes neither in stepUpRoutes nor stepUpExempt:\n  %s", strings.Join(unclassified, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("step-up catalogue names routes that are not mounted:\n  %s", strings.Join(stale, "\n  "))
	}
	if len(both) > 0 {
		t.Errorf("routes both gated and exempt:\n  %s", strings.Join(both, "\n  "))
	}
	// The catalogue must also build: every key a valid "METHOD /pattern".
	_ = (&mfa.Service{}).StepUpGate(gated)
}

// TestLinkedPhoneCallsPassCSRF: the mobile app answers approval requests and
// unlinks itself with its device credential, and links itself with a pairing
// code, sending no cookie, bearer token or Origin; those three calls must get
// past the CSRF check, and nothing else on the push-device paths may.
func TestLinkedPhoneCallsPassCSRF(t *testing.T) {
	reached := false
	h := httpx.CSRF(httpx.CSRFConfig{AllowedOrigins: []string{"https://console.example"}, ExemptPaths: csrfExemptPaths()})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	for path, want := range map[string]bool{
		"/v1/mfa/push/challenges/" + uuid.NewString() + "/respond": true,
		"/v1/mfa/push/devices/" + uuid.NewString() + "/unlink":     true,
		"/v1/mfa/push/pairing/claim":                               true,
		"/v1/mfa/push/devices":                                     false,
		"/v1/mfa/push/pairing":                                     false,
	} {
		reached = false
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil))
		if reached != want {
			t.Errorf("POST %s with no cookie, token or Origin: reached handler = %v, want %v", path, reached, want)
		}
	}
}
