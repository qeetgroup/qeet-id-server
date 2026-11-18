//go:build integration

package apitest

import (
	"net/http"
	"net/url"
)

// Browser is a person's browser on the hosted login: it keeps the cookies the API sets, and sends
// the page's Origin and, on a change, the CSRF token, as the hosted login's pages do.
type Browser struct {
	s       *Server
	cookies map[string]*http.Cookie
}

// Browser is a new browser with no cookies.
func (s *Server) Browser() *Browser {
	return &Browser{s: s, cookies: map[string]*http.Cookie{}}
}

// Do sends method path with body (JSON, when not nil) from the hosted login's page.
func (b *Browser) Do(method, path string, body any) *Response {
	b.s.t.Helper()
	if method != http.MethodGet && b.cookies["qe_csrf"] == nil {
		b.Do(http.MethodGet, "/healthz", nil) // any page load hands out the CSRF cookie
	}
	res := b.s.Send(func() *http.Request {
		req := b.s.request(method, path, "", body)
		req.Header.Set("Origin", b.s.cfg.LoginBaseURL)
		for _, c := range b.cookies {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		if c := b.cookies["qe_csrf"]; c != nil && method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", c.Value)
		}
		return req
	})
	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return res
}

// Has reports whether the browser holds the cookie name.
func (b *Browser) Has(name string) bool { return b.cookies[name] != nil }

// Location is where a redirect sends the browser, parsed.
func (r *Response) Location() *url.URL {
	u, _ := url.Parse(r.Header.Get("Location"))
	if u == nil {
		return &url.URL{}
	}
	return u
}
