// Package strutil holds the small string helpers many packages need: the
// pointer form of a nullable column or optional JSON field, a length cap and
// a comma-separated list.
package strutil

import "strings"

// NilIfEmpty returns &s, or nil for "".
func NilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Deref returns *p, or "" for nil.
func Deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Truncate returns s cut to at most n bytes.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// SplitList returns the trimmed, non-empty entries of a comma-separated list,
// nil when there are none.
func SplitList(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
