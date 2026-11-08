package mfa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// geoContext is a request's context as the trusted proxy's headers leave it.
func geoContext(t *testing.T, country, city string) context.Context {
	t.Helper()
	httpx.SetGeoCountryHeader("X-Test-Country")
	httpx.SetGeoCityHeader("X-Test-City")
	t.Cleanup(func() {
		httpx.SetGeoCountryHeader("")
		httpx.SetGeoCityHeader("")
	})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if country != "" {
		r.Header.Set("X-Test-Country", country)
	}
	if city != "" {
		r.Header.Set("X-Test-City", city)
	}
	var got context.Context
	httpx.GeoCountryContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Context()
	})).ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func TestPushLocation(t *testing.T) {
	cases := []struct{ name, country, city, want string }{
		{"city and country", "IN", "Bengaluru", "Bengaluru, India"},
		{"country only", "NG", "", "Nigeria"},
		{"city only", "", "Lagos", "Lagos"},
		{"neither", "", "", ""},
		{"lower-case code", "in", "Hyderabad", "Hyderabad, India"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pushLocation(geoContext(t, tc.country, tc.city)); got != tc.want {
				t.Fatalf("pushLocation = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCountryName(t *testing.T) {
	for code, want := range map[string]string{"IN": "India", "US": "United States", "": ""} {
		if got := countryName(code); got != want {
			t.Errorf("countryName(%q) = %q, want %q", code, got, want)
		}
	}
}
