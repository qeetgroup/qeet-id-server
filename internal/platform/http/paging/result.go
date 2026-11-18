package paging

import (
	"net/url"
	"strconv"
)

// Result is a list's body: its items (never null), next_cursor only when there
// is another page, and truncated only when a list with no paging was cut at
// MaxListItems. A body with more fields embeds it, and encoding/json flattens
// it:
//
//	type Page struct {
//		paging.Result[Event]
//		Total int `json:"total"`
//	}
type Result[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// Page is the Result of a keyset page: items, and next, the next page's cursor
// ("" on the last page). Page(Next(rows, limit, key)) reads both from rows.
func Page[T any](items []T, next string) Result[T] {
	if items == nil {
		items = []T{}
	}
	return Result[T]{Items: items, NextCursor: next}
}

// List is the Result of a list with no paging, read with LIMIT
// MaxListItems+1: its first MaxListItems items, truncated when some were left
// out.
func List[T any](items []T) Result[T] {
	items, truncated := Truncate(items)
	if items == nil {
		items = []T{}
	}
	return Result[T]{Items: items, Truncated: truncated}
}

// Clamp is limit as a page size: def when limit is below 1 (unset), and at
// most maximum.
func Clamp(limit, def, maximum int) int {
	if limit < 1 {
		return def
	}
	return min(limit, maximum)
}

// Limit is the page size the limit query parameter asks for: def when it is
// absent, malformed or below 1, and at most maximum.
func Limit(q url.Values, def, maximum int) int {
	n, err := strconv.Atoi(q.Get("limit"))
	if err != nil {
		return def
	}
	return Clamp(n, def, maximum)
}
