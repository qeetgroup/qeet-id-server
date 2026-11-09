// Package returnto checks where a browser may be sent once a sign-in it started on the hosted
// login finishes elsewhere (an identity provider): a path on the same site, or an absolute URL on
// an allowed origin. Anything else would make the sign-in host an open redirect.
package returnto

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Allowed is the set of origins a return address may point at, as "scheme://host[:port]".
type Allowed map[string]struct{}

// Origins builds the allowed set from URLs or origins; ones without a scheme and host are skipped.
func Origins(urls ...string) Allowed {
	set := make(Allowed, len(urls))
	for _, raw := range urls {
		if o := origin(raw); o != "" {
			set[o] = struct{}{}
		}
	}
	return set
}

func origin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// Valid reports whether returnTo is a root-relative path (one leading "/"), or an absolute URL
// without credentials on an allowed origin. Whitespace, control characters and backslashes are
// refused anywhere, as browsers rewrite or drop them.
func (a Allowed) Valid(returnTo string) bool {
	if returnTo == "" || !utf8.ValidString(returnTo) || strings.ContainsFunc(returnTo, func(r rune) bool {
		return r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return false
	}
	u, err := url.Parse(returnTo)
	if err != nil || u.User != nil {
		return false
	}
	if returnTo[0] == '/' {
		return !strings.HasPrefix(returnTo, "//") && u.Scheme == "" && u.Host == ""
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	_, ok := a[strings.ToLower(u.Scheme+"://"+u.Host)]
	return ok
}
