package http

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/policy"
	"github.com/qeetgroup/qeet-id/domains/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id/domains/access/mfa"
	"github.com/qeetgroup/qeet-id/domains/access/passkeys"
	"github.com/qeetgroup/qeet-id/domains/access/recovery"
	"github.com/qeetgroup/qeet-id/domains/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id/domains/developer/api-keys"
	"github.com/qeetgroup/qeet-id/domains/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id/domains/developer/service-accounts"
	"github.com/qeetgroup/qeet-id/domains/developer/webhooks"
	"github.com/qeetgroup/qeet-id/domains/federation/ldap"
	"github.com/qeetgroup/qeet-id/domains/federation/oidc"
	"github.com/qeetgroup/qeet-id/domains/federation/saml"
	"github.com/qeetgroup/qeet-id/domains/federation/scim"
	"github.com/qeetgroup/qeet-id/domains/federation/social"
	"github.com/qeetgroup/qeet-id/domains/identity/groups"
	"github.com/qeetgroup/qeet-id/domains/identity/invitations"
	"github.com/qeetgroup/qeet-id/domains/identity/organizations"
	"github.com/qeetgroup/qeet-id/domains/identity/organizations/branding"
	"github.com/qeetgroup/qeet-id/domains/identity/users"
	"github.com/qeetgroup/qeet-id/domains/identity/verification"
	"github.com/qeetgroup/qeet-id/domains/operations/analytics"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/domains/operations/billing"
	"github.com/qeetgroup/qeet-id/domains/operations/compliance"
	"github.com/qeetgroup/qeet-id/domains/operations/email-templates"
	"github.com/qeetgroup/qeet-id/domains/operations/retention"
	"github.com/qeetgroup/qeet-id/platform/health"
	"github.com/qeetgroup/qeet-id/platform/httpx"
	"github.com/qeetgroup/qeet-id/platform/outbox"
)

// testDeps builds a Deps with every handler field non-nil. The Mount* methods
// only REGISTER routes onto the chi router; they never execute the handlers,
// and chi.Walk does not invoke middleware or handlers. So zero-value structs
// are sufficient for route discovery — no DB pool, issuer, or config required.
//
// The one field that gates route registration is SAML.IdP: saml.Handler.Mount
// only mounts the IdP-side routes (/saml-providers...) when h.IdP != nil, so we
// set it to a zero-value &saml.IdP{} to exercise the full SAML surface.
func testDeps() Deps {
	return Deps{
		Tenant:         &tenant.Handler{},
		User:           &user.Handler{},
		Auth:           &auth.Handler{},
		AuthPolicy:     &authpolicy.Handler{},
		RBAC:           &rbac.Handler{},
		Verification:   &verification.Handler{},
		Recovery:       &recovery.Handler{},
		Retention:      &retention.Handler{},
		Invite:         &invite.Handler{},
		Branding:       &branding.Handler{},
		EmailTemplate:  &emailtemplate.Handler{},
		APIKey:         &apikey.Handler{},
		APIKeyService:  &apikey.Service{},
		Principal:      &principal.Handler{},
		MFA:            &mfa.Handler{},
		Webhook:        &webhook.Handler{},
		Policy:         &policy.Handler{},
		GDPR:           &gdpr.Handler{},
		Audit:          &audit.Handler{},
		Billing:        &billing.Handler{},
		Analytics:      &analytics.Handler{},
		Outbox:         &outbox.Handler{},
		OIDC:           &oidc.Handler{},
		Passkey:        &passkey.Handler{},
		Social:         &social.Handler{},
		Group:          &group.Handler{},
		SCIM:           &scim.Handler{},
		Secret:         &secret.Handler{},
		SAML:           &saml.Handler{IdP: &saml.IdP{}},
		LDAP:           &ldap.Handler{},
		IPAllow:        &ipallow.Handler{},
		Health:         &health.Handler{},
		InFlight:       &httpx.InFlight{},
		AuthVerifier:   &httpx.AuthVerifier{},
		AllowedOrigins: []string{"http://localhost:3000"},
		ServiceName:    "qeet-id-test",
		ServiceEnv:     "test",
		// CSRF stays enabled (default) so the CSRF middleware is wired exactly
		// as in production; chi.Walk never executes it.
	}
}

type route struct {
	method string
	path   string
}

func (r route) String() string { return r.method + " " + r.path }

// mountedRoutes walks the real router and returns the normalized
// (method, OpenAPI-path) set for the HTTP verbs we document. chi already emits
// {param} syntax, which is also OpenAPI's, so normalization is light: trim a
// trailing slash (except for the root "/") and skip the implicit OPTIONS/HEAD
// that chi/cors register.
func mountedRoutes(t *testing.T) map[route]bool {
	t.Helper()
	h := NewRouter(testDeps())
	r, ok := h.(chi.Routes)
	if !ok {
		t.Fatalf("NewRouter did not return a chi.Routes; got %T", h)
	}

	documented := map[string]bool{
		http.MethodGet:    true,
		http.MethodPost:   true,
		http.MethodPut:    true,
		http.MethodPatch:  true,
		http.MethodDelete: true,
	}

	out := map[route]bool{}
	err := chi.Walk(r, func(method, routePattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !documented[method] {
			return nil // skip OPTIONS / HEAD that chi + cors add implicitly
		}
		out[route{method: method, path: normalizePath(routePattern)}] = true
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	return out
}

func normalizePath(p string) string {
	// chi sometimes records mount points with a trailing "/*"; none of our
	// patterns use catch-alls, but guard anyway.
	p = strings.TrimSuffix(p, "/*")
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// specDoc is the minimal OpenAPI shape we need: paths -> path -> method -> op.
type specDoc struct {
	OpenAPI string                                       `yaml:"openapi"`
	Paths   map[string]map[string]map[string]interface{} `yaml:"paths"`
}

func loadSpec(t *testing.T) specDoc {
	t.Helper()
	// internal/http -> ../../api/openapi.yaml
	path := filepath.Join("..", "..", "api", "openapi.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc specDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s as YAML: %v", path, err)
	}
	if doc.OpenAPI == "" {
		t.Fatalf("%s: missing top-level openapi version", path)
	}
	return doc
}

// specRoutes flattens the spec into the same (method, path) set, lower/upper
// casing methods to match net/http verbs.
func specRoutes(doc specDoc) map[route]bool {
	out := map[route]bool{}
	for p, methods := range doc.Paths {
		for m := range methods {
			mu := strings.ToUpper(m)
			switch mu {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				out[route{method: mu, path: normalizePath(p)}] = true
			}
		}
	}
	return out
}

// skipCoverage is a deliberately tiny allow-list of mounted routes that need
// not appear in the OpenAPI document. The only entries are an artifact, not a
// real API surface: the Prometheus endpoint is mounted with r.Handle("/metrics",
// …), which registers the SAME handler for EVERY HTTP method. chi.Walk therefore
// reports /metrics under GET/POST/PUT/PATCH/DELETE. We document the meaningful
// GET /metrics in the spec and skip the four phantom verbs here. Everything
// else — including /healthz and /readyz — is documented.
var skipCoverage = map[route]bool{
	{method: http.MethodPost, path: "/metrics"}:   true,
	{method: http.MethodPut, path: "/metrics"}:    true,
	{method: http.MethodPatch, path: "/metrics"}:  true,
	{method: http.MethodDelete, path: "/metrics"}: true,
}

func TestOpenAPICoversAllMountedRoutes(t *testing.T) {
	mounted := mountedRoutes(t)
	doc := loadSpec(t)
	spec := specRoutes(doc)

	var missing []string
	for r := range mounted {
		if skipCoverage[r] {
			continue
		}
		if !spec[r] {
			missing = append(missing, r.String())
		}
	}
	sort.Strings(missing)

	t.Logf("router mounts %d documented routes; openapi.yaml documents %d", len(mounted), len(spec))

	if len(missing) > 0 {
		t.Errorf("%d mounted route(s) are NOT documented in api/openapi.yaml:\n%s",
			len(missing), strings.Join(missing, "\n"))
	}
}

// TestOpenAPIHasNoPhantomRoutes warns (does not fail) when the spec documents a
// route the router never mounts — catching drift in the other direction.
func TestOpenAPIHasNoPhantomRoutes(t *testing.T) {
	mounted := mountedRoutes(t)
	doc := loadSpec(t)
	spec := specRoutes(doc)

	var phantom []string
	for r := range spec {
		if !mounted[r] {
			phantom = append(phantom, r.String())
		}
	}
	sort.Strings(phantom)

	if len(phantom) > 0 {
		t.Logf("WARNING: %d documented route(s) are not mounted by the router (possible drift):\n%s",
			len(phantom), strings.Join(phantom, "\n"))
	}
}

// TestDumpMountedRoutes is not an assertion; it prints the full authoritative
// inventory (run with -v) so the spec can be regenerated from reality.
func TestDumpMountedRoutes(t *testing.T) {
	mounted := mountedRoutes(t)
	list := make([]string, 0, len(mounted))
	for r := range mounted {
		list = append(list, r.String())
	}
	sort.Strings(list)
	t.Logf("MOUNTED ROUTES (%d):\n%s", len(list), strings.Join(list, "\n"))
	fmt.Fprintf(os.Stderr, "=== INVENTORY START ===\n%s\n=== INVENTORY END ===\n", strings.Join(list, "\n"))
}
