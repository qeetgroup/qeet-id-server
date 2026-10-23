package httpx

import (
	"net/http"
	"strings"
)

// PublicOrigin returns the origin to build this API's absolute URLs on:
// configured, the API's public origin, when set. Otherwise it derives one
// from the request's Host, which a client controls, so production sets
// configured.
func PublicOrigin(r *http.Request, configured string) string {
	if base := strings.TrimRight(configured, "/"); base != "" {
		return base
	}
	return requestScheme(r) + "://" + r.Host
}

// requestScheme returns the request's public scheme: X-Forwarded-Proto from a
// TLS-terminating proxy, then the request's own TLS state, and https for any
// host but localhost or 127.0.0.1.
func requestScheme(r *http.Request) string {
	if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	if h := r.Host; strings.HasPrefix(h, "localhost") || strings.HasPrefix(h, "127.0.0.1") {
		return "http"
	}
	return "https"
}
