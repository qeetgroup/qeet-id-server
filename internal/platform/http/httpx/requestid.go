package httpx

import "net/http"

// RequestIDHeader sends the request's ID back as X-Request-Id on every
// response, so a caller can quote it for a success as well as for an error
// (whose body carries it as request_id). Mount it after chi's RequestID, which
// assigns the ID or keeps the caller's own.
func RequestIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := RequestID(r); id != "" {
			w.Header().Set("X-Request-Id", id)
		}
		next.ServeHTTP(w, r)
	})
}
