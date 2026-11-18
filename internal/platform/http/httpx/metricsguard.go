package httpx

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// MetricsGuard serves next only to a caller presenting token as a bearer
// token, or, with no token, to anyone where open (development). Otherwise it
// answers 404, as if there were no metrics.
func MetricsGuard(token string, open bool, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			if open {
				next.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	}
}
