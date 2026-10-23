package httpx

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
)

// The approximate country of a request comes only from a header a trusted
// upstream proxy sets (GEO_COUNTRY_HEADER, e.g. CloudFront-Viewer-Country or
// CF-IPCountry), never from anything the client chooses: with no header
// configured there is no country. It is an ISO 3166-1 alpha-2 code, or "".

var geoCountryHeader atomic.Value // string

const ctxKeyGeoCountry ctxKey = "qeet.geo_country"

// SetGeoCountryHeader names the trusted upstream header carrying the
// request's country ("" = none). Call it from the composition root before
// serving.
func SetGeoCountryHeader(name string) { geoCountryHeader.Store(strings.TrimSpace(name)) }

// GeoCountryContext puts the request's country, when the trusted header
// gives a well-formed one, in its context for GeoCountry.
func GeoCountryContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, _ := geoCountryHeader.Load().(string)
		if name != "" {
			if c := strings.ToUpper(strings.TrimSpace(r.Header.Get(name))); isCountryCode(c) {
				r = r.WithContext(context.WithValue(r.Context(), ctxKeyGeoCountry, c))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// GeoCountry is the request's approximate country, or "" when unknown.
func GeoCountry(ctx context.Context) string {
	c, _ := ctx.Value(ctxKeyGeoCountry).(string)
	return c
}

// isCountryCode accepts two letters A–Z, excluding the "XX"/"T1" style
// placeholders proxies use for unknown or anonymised origins.
func isCountryCode(c string) bool {
	if len(c) != 2 || c == "XX" || c == "ZZ" {
		return false
	}
	return c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z'
}
