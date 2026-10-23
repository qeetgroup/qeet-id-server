package paging

// MaxListItems caps a list endpoint that has no paging: a longer list answers
// with its first MaxListItems items and "truncated": true. Its query reads
// LIMIT MaxListItems+1, so the extra row tells.
const MaxListItems = 1000

// Truncate cuts items to MaxListItems and reports whether any were left out.
func Truncate[T any](items []T) ([]T, bool) {
	if len(items) > MaxListItems {
		return items[:MaxListItems], true
	}
	return items, false
}

// List is the body of such a list: its items, and "truncated" only when some
// were left out.
func List[T any](items []T) map[string]any {
	items, truncated := Truncate(items)
	body := map[string]any{"items": items}
	if truncated {
		body["truncated"] = true
	}
	return body
}
