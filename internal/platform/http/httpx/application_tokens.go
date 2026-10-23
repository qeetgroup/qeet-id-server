package httpx

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// RefuseApplicationTokens answers 403 auth.application_token to a request made
// with an application's token (Principal.ClientID set) unless its route matches
// an allowed "METHOD /pattern" entry in chi syntax: such a token may read who
// the user is, not manage the account. Mount it after RequireAuth.
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
