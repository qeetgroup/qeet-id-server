package postgres

import "strings"

// likeEscaper escapes the LIKE metacharacters, backslash first.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// EscapeLike makes s match itself in a LIKE or ILIKE pattern, under the
// default escape character (backslash): a % or _ a person typed is then no
// wildcard. Wrap the result in % for a substring search.
func EscapeLike(s string) string { return likeEscaper.Replace(s) }
