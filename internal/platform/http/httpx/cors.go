package httpx

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/cors"
)

// CORSConfig is who may read which responses from another origin.
type CORSConfig struct {
	// Operator are the operator's own origins (the console, the hosted
	// login). Headers and Exposed are the request headers they may send and
	// the response headers they may read, besides the server's own.
	Operator         []string
	Headers, Exposed []string
	// PublicPaths answer any origin, without credentials.
	PublicPaths []string
	// AppPaths answer an origin AppOrigin allows, without credentials.
	AppPaths  []string
	AppOrigin func(ctx context.Context, origin string) bool
}

// CORS answers cross-origin requests: the operator's origins may send credentials anywhere; the
// public paths answer any origin without credentials; the application paths answer an origin an
// application allows (AppOrigin), without credentials, so a page reads only what its own request
// gets. Nothing is ever allowed for every origin with credentials.
func CORS(c CORSConfig) func(http.Handler) http.Handler {
	operator := cors.Handler(cors.Options{
		AllowedOrigins:   c.Operator,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   append([]string{"Authorization", "Content-Type", "X-Request-Id", "X-Dev-User", "X-Dev-Organization", csrfHeaderName}, c.Headers...),
		ExposedHeaders:   append([]string{"X-Request-Id"}, c.Exposed...),
		AllowCredentials: true,
		MaxAge:           300,
	})
	public := cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "OPTIONS"},
		MaxAge:         300,
	})
	app := cors.Handler(cors.Options{
		AllowOriginFunc: func(r *http.Request, origin string) bool {
			return c.AppOrigin != nil && c.AppOrigin(r.Context(), origin)
		},
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		ExposedHeaders: []string{"WWW-Authenticate"},
		MaxAge:         300,
	})
	operatorOrigin := func(origin string) bool {
		return slices.ContainsFunc(c.Operator, func(a string) bool { return strings.EqualFold(a, origin) })
	}
	return func(next http.Handler) http.Handler {
		viaOperator, viaPublic, viaApp := operator(next), public(next), app(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case slices.Contains(c.PublicPaths, r.URL.Path):
				viaPublic.ServeHTTP(w, r)
			case slices.Contains(c.AppPaths, r.URL.Path) && !operatorOrigin(r.Header.Get("Origin")):
				viaApp.ServeHTTP(w, r)
			default:
				viaOperator.ServeHTTP(w, r)
			}
		})
	}
}
