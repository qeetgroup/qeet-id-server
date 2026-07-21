// Package dbutil holds small helpers shared by repositories — JSONB decoding
// and dynamic UPDATE assembly — so each domain doesn't re-implement them.
package dbutil

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
)

// Metadata decodes a JSONB column into a map, never returning nil. Postgres
// guarantees JSONB is valid JSON, so a decode failure means a codec mismatch
// or corruption; it's logged and yields an empty map rather than a hard error.
func Metadata(raw []byte) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		slog.Warn("jsonb decode failed", "err", err, "bytes", len(raw))
		return map[string]any{}
	}
	if m == nil {
		return map[string]any{}
	}
	return m
}

// UpdateBuilder assembles a parameterized "SET a = $1, b = $2, ..." clause for
// dynamic UPDATEs, tracking placeholder indexes so callers don't manage them.
type UpdateBuilder struct {
	sets []string
	args []any
}

func NewUpdate() *UpdateBuilder { return &UpdateBuilder{} }

// Set adds "col = $N" bound to val. Column names must be trusted literals.
func (u *UpdateBuilder) Set(col string, val any) {
	u.args = append(u.args, val)
	u.sets = append(u.sets, col+" = $"+strconv.Itoa(len(u.args)))
}

// SetRaw adds a literal assignment with no bound value, e.g. "updated_at = NOW()".
func (u *UpdateBuilder) SetRaw(assignment string) {
	u.sets = append(u.sets, assignment)
}

// Empty reports whether no assignment has been added yet.
func (u *UpdateBuilder) Empty() bool { return len(u.sets) == 0 }

// Assignments returns the joined SET body, e.g. "name = $1, updated_at = NOW()".
func (u *UpdateBuilder) Assignments() string { return strings.Join(u.sets, ", ") }

// Args returns the bound values in placeholder order.
func (u *UpdateBuilder) Args() []any { return u.args }

// NextPlaceholder is the $N a caller should use for the next bound value
// (e.g. the trailing WHERE id = $N), i.e. len(args)+1.
func (u *UpdateBuilder) NextPlaceholder() int { return len(u.args) + 1 }
