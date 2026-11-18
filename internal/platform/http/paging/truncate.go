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

// ListWith is List's body as a map, with the body's other fields beside its
// items. A body with fixed other fields is better a struct embedding Result.
func ListWith[T any](items []T, fields map[string]any) map[string]any {
	list := List(items)
	body := map[string]any{"items": list.Items}
	if list.Truncated {
		body["truncated"] = true
	}
	for k, v := range fields {
		body[k] = v
	}
	return body
}
