package rbac

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Checker decides whether a user holds a permission in a tenant. *Repository
// and decide.Decider satisfy it.
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
// route; a route absent from the policy table is denied. An application's
// token needs ApplicationScope as well as its user's UserPermission, so it
// holds only the overlap of what the user may do and what the user approved.
type RoutePolicy struct {
	UserPermission           string   // permission a user's role must grant ("" = none)
	ApplicationScope         string   // scope an application's token must carry ("" = refused)
	MachineScopes            []string // a machine principal needs one of these
	AllowUser                bool     // users may call the route
	AllowAPIKey              bool     // API keys may call it
	AllowService             bool     // service principals may call it
	AllowAgent               bool     // agents may call it
	HandlerAuthorizedMachine bool     // the handler checks a resource-derived machine scope (vault:<name>)
}

// PermissionPolicy gates a route on one permission: a user's role must grant
// it, and a machine credential or an application's token must carry it as a
// scope, so an application approved for user.read can read users only where
// its user may.
func PermissionPolicy(permission string) RoutePolicy {
	return RoutePolicy{
		UserPermission:   permission,
		ApplicationScope: permission,
		MachineScopes:    []string{permission},
		AllowUser:        true,
		AllowAPIKey:      true,
		AllowService:     true,
		AllowAgent:       true,
	}
}

// UserOnlyPolicy is a self-service route: a user's own resource, closed to
// machine credentials, reachable by an application's token only with scope.
func UserOnlyPolicy(scope string) RoutePolicy {
	return RoutePolicy{AllowUser: true, ApplicationScope: scope}
}

// HandlerAuthorizedPolicy admits every machine principal and leaves its scope
// check to the handler; users are admitted when allowUser is set.
func HandlerAuthorizedPolicy(allowUser bool, scope string) RoutePolicy {
	return RoutePolicy{
		AllowUser:                allowUser,
		ApplicationScope:         scope,
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

// Enforce gates authenticated routes by a policy map keyed "METHOD /pattern"
// in chi syntax (e.g. "POST /v1/users"); an unlisted route is denied. Mount it
// once on the authenticated group, after RequireAuth. It matches the concrete
// path itself, as chi's RoutePattern isn't reliably resolved in group middleware.
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
	// Two patterns can match one path ("/v1/vault/{name}" and "/v1/vault/tokens").
	// Sort literal-first, as chi does, then by pattern, so every process applies
	// the same policy rather than whichever map order picked.
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

			refusal, challenge, err := ruling(r.Context(), c, p, policy)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			if refusal != nil {
				if challenge != "" {
					w.Header().Set("WWW-Authenticate", challenge)
				}
				httpx.WriteError(w, r, refusal)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Allows reports whether p may use a route with policy, as Enforce decides it:
// for a handler that must decide again while a long request runs.
func Allows(ctx context.Context, c Checker, p *httpx.Principal, policy RoutePolicy) (bool, error) {
	refusal, _, err := ruling(ctx, c, p, policy)
	return err == nil && refusal == nil, err
}

// ruling is Enforce's decision for p on a route with policy: a nil refusal
// lets it through, else refusal is the error to answer with, and challenge
// the WWW-Authenticate header to send, if any. err is a fault, not a refusal.
func ruling(ctx context.Context, c Checker, p *httpx.Principal, policy RoutePolicy) (refusal error, challenge string, err error) {
	switch p.ActorType {
	case "", "user":
		if !policy.AllowUser || p.UserID == nil {
			return errs.ErrRBACPermissionDenied, "", nil
		}
		// A token issued to an application acts for its user only as far as
		// the user approved: it needs the route's scope, and then the user's
		// permission below like any other request.
		if p.ClientID != "" && (policy.ApplicationScope == "" || !slices.Contains(p.Scopes, policy.ApplicationScope)) {
			challenge := `Bearer realm="qeet", error="insufficient_scope"`
			if policy.ApplicationScope != "" {
				challenge += `, scope="` + policy.ApplicationScope + `"`
			}
			return errs.ErrAuthInsufficientScope.WithDetail("this request needs the " + policy.ApplicationScope + " scope"), challenge, nil
		}
		if policy.UserPermission != "" {
			if p.TenantID == nil {
				return errs.ErrForbidden.WithDetail("tenant scope required"), "", nil
			}
			allowed, err := c.Check(ctx, *p.UserID, *p.TenantID, policy.UserPermission)
			if err != nil {
				return nil, "", err
			}
			if !allowed {
				return errs.ErrRBACPermissionDenied, "", nil
			}
		}
	case "api_key":
		if !policy.AllowAPIKey || !machineScopeAllowed(p, policy) {
			return errs.ErrRBACPermissionDenied, "", nil
		}
		if p.UserID != nil {
			held, err := personHoldsKeyScope(ctx, c, p, policy)
			if err != nil || !held {
				return errs.ErrRBACPermissionDenied, "", err
			}
		}
	case "service", "service_principal":
		if !policy.AllowService || !machineScopeAllowed(p, policy) {
			return errs.ErrRBACPermissionDenied, "", nil
		}
	case "agent":
		if !policy.AllowAgent || !machineScopeAllowed(p, policy) {
			return errs.ErrRBACPermissionDenied, "", nil
		}
	default:
		return errs.ErrRBACPermissionDenied, "", nil
	}
	return nil, "", nil
}

// personHoldsKeyScope reports whether the person a personal key acts for
// still holds a permission the key carries for the route, so the key does only
// what both its scopes and their permissions now allow. A route whose handler
// checks a vault scope needs their secret.read.
func personHoldsKeyScope(ctx context.Context, c Checker, p *httpx.Principal, policy RoutePolicy) (bool, error) {
	if p.TenantID == nil {
		return false, nil
	}
	wants := policy.MachineScopes
	if policy.HandlerAuthorizedMachine {
		wants = []string{"secret.read"}
	}
	for _, want := range wants {
		if !policy.HandlerAuthorizedMachine && !slices.Contains(p.Scopes, want) {
			continue
		}
		if held, err := c.Check(ctx, *p.UserID, *p.TenantID, want); err != nil || held {
			return held, err
		}
	}
	return false, nil
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
