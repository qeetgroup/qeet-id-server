package httpx

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// RefuseApplicationTokens refuses a request authenticated by a token issued
// to an application (Principal.ClientID set) with 403 auth.application_token,
// unless its route is listed in allowed. An application's token was approved
// for that application — reading who the user is — not for managing the
// account or the organisation, which only the user's own tokens may do. Mount
// it on the authenticated route group, after RequireAuth.
//
// allowed are "METHOD /path" entries in chi pattern syntax ("{id}" matches one
// path segment); keep the list to the endpoints meant for applications.
func RefuseApplicationTokens(allowed []string) func(http.Handler) http.Handler {
	listed := chi.NewRouter()
	for _, route := range allowed {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("httpx: application-token route without a method: " + route)
		}
		listed.MethodFunc(method, pattern, func(http.ResponseWriter, *http.Request) {})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFromCtx(r.Context())
			if p == nil || p.ClientID == "" || listed.Match(chi.NewRouteContext(), r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			WriteError(w, r, errs.ErrAuthApplicationToken)
		})
	}
}
