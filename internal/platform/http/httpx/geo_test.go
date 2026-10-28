package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGeoCountryComesOnlyFromTheTrustedHeader(t *testing.T) {
	var got string
	h := GeoCountryContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = GeoCountry(r.Context()) }))
	for _, c := range []struct{ header, value, want string }{
		{"", "IN", ""},
		{"CF-IPCountry", "in", "IN"},
		{"CF-IPCountry", "XX", ""},
		{"CF-IPCountry", "India", ""},
		{"CF-IPCountry", "", ""},
	} {
		SetGeoCountryHeader(c.header)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("CF-IPCountry", c.value)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got != c.want {
			t.Errorf("header %q value %q: country %q, want %q", c.header, c.value, got, c.want)
		}
	}
	SetGeoCountryHeader("")
}

// TestGeoCountryHeaderIsReported checks that whether a country header is
// named, and when one last gave a country, are reported.
func TestGeoCountryHeaderIsReported(t *testing.T) {
	SetGeoCountryHeader("")
	if GeoCountryHeaderConfigured() {
		t.Error("no header named, but reported as configured")
	}
	SetGeoCountryHeader("CF-IPCountry")
	defer SetGeoCountryHeader("")
	if !GeoCountryHeaderConfigured() {
		t.Error("a header named, but reported as not configured")
	}
	before := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("CF-IPCountry", "IN")
	GeoCountryContext(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)
	if seen := GeoCountryLastSeen(); seen == nil || seen.Before(before.Add(-time.Second)) {
		t.Errorf("last seen %v after a request with a country, want about now", seen)
	}
}
