package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoStoreMarksListedRoutesOnly(t *testing.T) {
	h := NoStore([]string{
		"POST /v1/oauth/token",
		"POST /v1/tenants/{tenantID}/clients/{id}/rotate-secret",
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/v1/oauth/token", true},
		{http.MethodPost, "/v1/tenants/t-1/clients/c-1/rotate-secret", true},
		{http.MethodGet, "/v1/oauth/token", false},
		{http.MethodPost, "/v1/oauth/token/extra", false},
		{http.MethodPost, "/v1/tenants/t-1/clients", false},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		cache, pragma := rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma")
		if tc.want && (cache != "no-store" || pragma != "no-cache") {
			t.Errorf("%s %s: Cache-Control %q, Pragma %q; want no-store, no-cache", tc.method, tc.path, cache, pragma)
		}
		if !tc.want && (cache != "" || pragma != "") {
			t.Errorf("%s %s: Cache-Control %q, Pragma %q; want neither", tc.method, tc.path, cache, pragma)
		}
	}
}

func TestNoStoreRefusesAnEntryWithoutAMethod(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NoStore accepted an entry without a method")
		}
	}()
	NoStore([]string{"/v1/oauth/token"})
}
