package httpx

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// SetNoStore marks a response as not to be stored by any cache, as RFC 6749
// §5.1 requires of a response carrying a token or credential. Pragma is for
// HTTP/1.0 caches.
func SetNoStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

// NoStore applies SetNoStore to requests whose route matches one of routes,
// "METHOD /pattern" entries in chi syntax over the full request path. Mount it
// on the root router.
func NoStore(routes []string) func(http.Handler) http.Handler {
	listed := chi.NewRouter()
	for _, route := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("httpx: no-store route without a method: " + route)
		}
		listed.MethodFunc(method, pattern, func(http.ResponseWriter, *http.Request) {})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The path chi routes on, so a request matches here as it does there.
			path := r.URL.Path
			if r.URL.RawPath != "" {
				path = r.URL.RawPath
			}
			if listed.Match(chi.NewRouteContext(), r.Method, path) {
				SetNoStore(w)
			}
			next.ServeHTTP(w, r)
		})
	}
}
