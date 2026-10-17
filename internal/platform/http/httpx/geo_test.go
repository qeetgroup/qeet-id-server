package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
