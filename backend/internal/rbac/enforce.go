package rbac

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/internal/platform/errs"
	"github.com/qeetgroup/qeet-id/internal/platform/httpx"
)

// Checker decides whether a user holds a permission in a tenant. *Repository
// satisfies it; kept as an interface so the HTTP layer depends on the behaviour,
// not the concrete repo.
type Checker interface {
	Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error)
}

type compiledRoute struct {
	re   *regexp.Regexp
	perm string
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
// middleware). It enforces ONLY for end-user principals (ActorType "user");
// API-key and service-principal callers carry no RBAC roles — they're
// authorized by their key scopes / OAuth grants — so they pass through. Routes
// absent from the map (public, self-service, tenant-create) also pass through.
func Enforce(c Checker, perms map[string]string) func(http.Handler) http.Handler {
	byMethod := map[string][]compiledRoute{}
	for key, perm := range perms {
		method, pattern, ok := strings.Cut(key, " ")
		if !ok {
			continue
		}
		byMethod[method] = append(byMethod[method], compiledRoute{re: patternToRegex(pattern), perm: perm})
	}

	lookup := func(method, path string) (string, bool) {
		for _, cr := range byMethod[method] {
			if cr.re.MatchString(path) {
				return cr.perm, true
			}
		}
		return "", false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := httpx.PrincipalFromCtx(r.Context())
			// Only RBAC-bearing end users are gated here.
			if p == nil || p.ActorType != "user" || p.UserID == nil {
				next.ServeHTTP(w, r)
				return
			}
			perm, ok := lookup(r.Method, r.URL.Path)
			if !ok {
				next.ServeHTTP(w, r) // route not gated by RBAC
				return
			}
			if p.TenantID == nil {
				httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("tenant scope required"))
				return
			}
			allowed, err := c.Check(r.Context(), *p.UserID, *p.TenantID, perm)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			if !allowed {
				httpx.WriteError(w, r, errs.ErrForbidden.
					WithMessage("You don't have permission to do that.").
					WithDetail("missing permission: "+perm))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
