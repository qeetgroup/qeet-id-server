package mfa

import (
	"context"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// pushLocation is where a request for approval comes from, as the phone shows
// it under "Near": "Bengaluru, India", the country alone, or "" when the
// trusted proxy gives no country or city (GEO_COUNTRY_HEADER, GEO_CITY_HEADER).
// It is approximate, from the request's IP address.
func pushLocation(ctx context.Context) string {
	city, country := httpx.GeoCity(ctx), countryName(httpx.GeoCountry(ctx))
	switch {
	case city != "" && country != "":
		return city + ", " + country
	case country != "":
		return country
	default:
		return city
	}
}

// countryName is an ISO 3166-1 alpha-2 code's English name ("IN" → "India"),
// or the code itself when it isn't one x/text knows.
func countryName(code string) string {
	if code == "" {
		return ""
	}
	region, err := language.ParseRegion(code)
	if err != nil {
		return code
	}
	if name := display.English.Regions().Name(region); name != "" {
		return name
	}
	return code
}
