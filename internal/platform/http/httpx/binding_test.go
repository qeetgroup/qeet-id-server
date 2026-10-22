package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// carry returns a request holding the cookies a response set.
func carry(rr *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge >= 0 {
			r.AddCookie(c)
		}
	}
	return r
}

func TestBindingCookieHoldsOnlyWhatThisBrowserBegan(t *testing.T) {
	b := BindingCookie{Name: "qe_test", Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: time.Minute}
	rr := httptest.NewRecorder()
	b.Add(rr, httptest.NewRequest(http.MethodGet, "/", nil), "first")
	c := rr.Result().Cookies()[0]
	if c.Name != "__Host-qe_test" || c.Path != "/" || !c.HttpOnly || !c.Secure || c.Domain != "" {
		t.Fatalf("cookie = %+v, want a __Host- HttpOnly Secure cookie on / with no domain", c)
	}
	r := carry(rr)
	if !b.Holds(r, "first") || b.Holds(r, "second") || b.Holds(r, "") {
		t.Fatal("holds the wrong ceremonies")
	}
	if (BindingCookie{Name: "qe_test"}).Holds(r, "first") {
		t.Fatal("an unprefixed cookie name read the prefixed cookie")
	}

	// Several ceremonies in flight, the oldest dropped past the limit.
	for _, id := range []string{"second", "third", "fourth", "fifth"} {
		rr = httptest.NewRecorder()
		b.Add(rr, r, id)
		r = carry(rr)
	}
	if b.Holds(r, "first") || !b.Holds(r, "second") || !b.Holds(r, "fifth") {
		t.Fatalf("after five ceremonies the cookie is %q, want the last four", r.Header.Get("Cookie"))
	}

	rr = httptest.NewRecorder()
	b.Remove(rr, r, "third")
	r = carry(rr)
	if b.Holds(r, "third") || !b.Holds(r, "second") {
		t.Fatal("remove forgot the wrong ceremony")
	}
	for _, id := range []string{"second", "fourth", "fifth"} {
		rr = httptest.NewRecorder()
		b.Remove(rr, r, id)
		r = carry(rr)
	}
	if got := rr.Result().Cookies(); len(got) != 1 || got[0].MaxAge != -1 {
		t.Fatalf("removing the last ceremony = %+v, want the cookie expired", got)
	}
}

func TestDecodeStrictJSONRefusesBodiesNotSentAsJSON(t *testing.T) {
	for contentType, want := range map[string]error{
		"application/json":                  nil,
		"application/json; charset=utf-8":   nil,
		"application/merge-patch+json":      nil,
		"text/plain":                        errs.ErrUnsupportedMediaType,
		"text/plain; charset=UTF-8":         errs.ErrUnsupportedMediaType,
		"application/x-www-form-urlencoded": errs.ErrUnsupportedMediaType,
		"multipart/form-data; boundary=x":   errs.ErrUnsupportedMediaType,
		"":                                  errs.ErrUnsupportedMediaType,
	} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"a":"b"}`))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		var out struct {
			A string `json:"a"`
		}
		err := DecodeStrictJSON(r, &out)
		if want == nil && (err != nil || out.A != "b") {
			t.Errorf("%q: %v, want decoded", contentType, err)
		}
		if want != nil && !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", contentType, err, want)
		}
	}
}
