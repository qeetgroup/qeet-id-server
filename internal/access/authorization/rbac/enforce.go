package rbac

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Checker decides whether a user holds a permission in a tenant. *Repository
// satisfies it; kept as an interface so the HTTP layer depends on the behaviour,
// not the concrete repo.
type Checker interface {
	Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error)
}

type compiledRoute struct {
	pattern   string
	re        *regexp.Regexp
	wildcards int
	policy    RoutePolicy
}

// RoutePolicy is the complete authorization contract for one authenticated
// route. Administrative routes use PermissionPolicy; self-service routes must
// opt in with UserOnlyPolicy. Absence from the policy table always denies.
type RoutePolicy struct {
	UserPermission string
	MachineScopes  []string
	AllowUser      bool
	AllowAPIKey    bool
	AllowService   bool
	AllowAgent     bool
	// HandlerAuthorizedMachine is reserved for routes whose machine scope is
	// resource-derived (for example vault:<name>) and is checked by the handler.
	HandlerAuthorizedMachine bool
}

func PermissionPolicy(permission string) RoutePolicy {
	return RoutePolicy{
		UserPermission: permission,
		MachineScopes:  []string{permission},
		AllowUser:      true,
		AllowAPIKey:    true,
		AllowService:   true,
		AllowAgent:     true,
	}
}

func UserOnlyPolicy() RoutePolicy { return RoutePolicy{AllowUser: true} }

func HandlerAuthorizedPolicy(allowUser bool) RoutePolicy {
	return RoutePolicy{
		AllowUser:                allowUser,
		AllowAPIKey:              true,
		AllowService:             true,
		AllowAgent:               true,
		HandlerAuthorizedMachine: true,
	}
}

// patternToRegex turns a chi-style route pattern ("/v1/users/{id}/mfa") into an
// anchored regex that matches a concrete path ("/v1/users/abc/mfa"). Param
// segments ({...}) become a single non-slash run; literals are escaped.
func patternToRegex(pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			parts[i] = "[^/]+"
		} else {
			parts[i] = regexp.QuoteMeta(p)
		}
	}
	return regexp.MustCompile("^" + strings.Join(parts, "/") + "$")
}

// Enforce gates authenticated routes against a route→permission map keyed by
// "METHOD /chi/route/pattern" (e.g. "POST /v1/users"). Mount it once on the
// authenticated router group, after RequireAuth.
//
// It matches the request's method + concrete path against the patterns itself
// (rather than chi's RoutePattern(), which isn't reliably resolved inside group
// middleware). Every authenticated route must be explicitly classified; an
// unknown route is denied. Users are checked through RBAC, while machine
// principals must carry one of the policy's exact scopes.
func Enforce(c Checker, policies map[string]RoutePolicy) func(http.Handler) http.Handler {
	byMethod := map[string][]compiledRoute{}
	for key, policy := range policies {
		method, pattern, ok := strings.Cut(key, " ")
		if !ok {
			continue
		}
		byMethod[method] = append(byMethod[method], compiledRoute{
			pattern:   pattern,
			re:        patternToRegex(pattern),
			wildcards: strings.Count(pattern, "{"),
			policy:    policy,
		})
	}
	// Two patterns can match one concrete path — "/v1/vault/{name}" also matches
	// "/v1/vault/tokens", which is separately classified. Ranging over a Go map
	// would pick a winner by iteration order, so the policy applied to such a
	// path could differ between processes. Sort literal-first (chi's own
	// precedence), then by pattern for a total order.
	for method := range byMethod {
		routes := byMethod[method]
		sort.SliceStable(routes, func(i, j int) bool {
			if routes[i].wildcards != routes[j].wildcards {
				return routes[i].wildcards < routes[j].wildcards
			}
			return routes[i].pattern < routes[j].pattern
		})
	}

	lookup := func(method, path string) (RoutePolicy, bool) {
		for _, cr := range byMethod[method] {
			if cr.re.MatchString(path) {
				return cr.policy, true
			}
		}
		return RoutePolicy{}, false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := httpx.PrincipalFromCtx(r.Context())
			if p == nil {
				httpx.WriteError(w, r, errs.ErrForbidden)
				return
			}
			policy, ok := lookup(r.Method, r.URL.Path)
			if !ok {
				httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("route has no authorization policy"))
				return
			}

			switch p.ActorType {
			case "", "user":
				if !policy.AllowUser || p.UserID == nil {
					httpx.WriteError(w, r, errs.ErrRBACPermissionDenied)
					return
				}
				if policy.UserPermission != "" {
					if p.TenantID == nil {
						httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant scope required"))
						return
					}
					allowed, err := c.Check(r.Context(), *p.UserID, *p.TenantID, policy.UserPermission)
					if err != nil {
						httpx.WriteError(w, r, err)
						return
					}
					if !allowed {
						httpx.WriteError(w, r, errs.ErrRBACPermissionDenied)
						return
					}
				}
			case "api_key":
				if !policy.AllowAPIKey || !machineScopeAllowed(p, policy) {
					httpx.WriteError(w, r, errs.ErrRBACPermissionDenied)
					return
				}
			case "service", "service_principal":
				if !policy.AllowService || !machineScopeAllowed(p, policy) {
					httpx.WriteError(w, r, errs.ErrRBACPermissionDenied)
					return
				}
			case "agent":
				if !policy.AllowAgent || !machineScopeAllowed(p, policy) {
					httpx.WriteError(w, r, errs.ErrRBACPermissionDenied)
					return
				}
			default:
				httpx.WriteError(w, r, errs.ErrRBACPermissionDenied)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func machineScopeAllowed(p *httpx.Principal, policy RoutePolicy) bool {
	if policy.HandlerAuthorizedMachine {
		return true
	}
	for _, have := range p.Scopes {
		for _, want := range policy.MachineScopes {
			if have == want {
				return true
			}
		}
	}
	return false
}
