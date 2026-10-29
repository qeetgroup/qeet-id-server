package httpx

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// The approximate country of a request comes only from a header a trusted
// upstream proxy sets (GEO_COUNTRY_HEADER, e.g. CloudFront-Viewer-Country or
// CF-IPCountry), never from anything the client chooses: with no header
// configured there is no country. It is an ISO 3166-1 alpha-2 code, or "".

var (
	geoCountryHeader atomic.Value // string
	geoCountrySeen   atomic.Int64 // Unix nanoseconds of the last request it gave a country; 0: none yet
	geoCityHeader    atomic.Value // string
)

const (
	ctxKeyGeoCountry ctxKey = "qeet.geo_country"
	ctxKeyGeoCity    ctxKey = "qeet.geo_city"
)

// maxCityLength bounds the city a header may give.
const maxCityLength = 100

// SetGeoCountryHeader names the trusted upstream header carrying the
// request's country ("" = none). Call it from the composition root before
// serving.
func SetGeoCountryHeader(name string) { geoCountryHeader.Store(strings.TrimSpace(name)) }

// SetGeoCityHeader names the trusted upstream header carrying the request's
// city, such as CloudFront-Viewer-City ("" = none).
func SetGeoCityHeader(name string) { geoCityHeader.Store(strings.TrimSpace(name)) }

// GeoCountryContext puts the request's country, when the trusted header
// gives a well-formed one, in its context for GeoCountry, and its city, when
// that header gives one, for GeoCity.
func GeoCountryContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, _ := geoCountryHeader.Load().(string)
		if name != "" {
			if c := strings.ToUpper(strings.TrimSpace(r.Header.Get(name))); isCountryCode(c) {
				r = r.WithContext(context.WithValue(r.Context(), ctxKeyGeoCountry, c))
				geoCountrySeen.Store(time.Now().UnixNano())
			}
		}
		if name, _ := geoCityHeader.Load().(string); name != "" {
			if city := cleanCity(r.Header.Get(name)); city != "" {
				r = r.WithContext(context.WithValue(r.Context(), ctxKeyGeoCity, city))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// cleanCity is a header's city, URL-decoded as CloudFront sends it, or "" when
// it is empty, too long or holds control characters.
func cleanCity(raw string) string {
	if decoded, err := url.QueryUnescape(raw); err == nil {
		raw = decoded
	}
	city := strings.TrimSpace(raw)
	if city == "" || len(city) > maxCityLength || !utf8.ValidString(city) {
		return ""
	}
	for _, c := range city {
		if unicode.IsControl(c) {
			return ""
		}
	}
	return city
}

// GeoCity is the request's approximate city, or "" when unknown.
func GeoCity(ctx context.Context) string {
	c, _ := ctx.Value(ctxKeyGeoCity).(string)
	return c
}

// GeoCountryHeaderConfigured reports whether a trusted country header is named.
func GeoCountryHeaderConfigured() bool {
	name, _ := geoCountryHeader.Load().(string)
	return name != ""
}

// GeoCountryLastSeen is when this instance last read a country from the
// trusted header, or nil if it hasn't since it started.
func GeoCountryLastSeen() *time.Time {
	n := geoCountrySeen.Load()
	if n == 0 {
		return nil
	}
	t := time.Unix(0, n).UTC()
	return &t
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
