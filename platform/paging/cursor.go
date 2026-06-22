// Package paging holds shared helpers for opaque cursor-based
// pagination. Right now there's only one shape — (created_at, id) —
// because every domain table in the repo orders by that pair. If a
// new table needs a different sort key, add a second helper rather
// than generalising prematurely.
package paging

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/errs"
)

// EncodeTimeUUID packs (created_at, id) into a base64url-encoded
// "RFC3339Nano|uuid" pair. The pair is used as a row's stable
// pagination key — the database compares it against (created_at, id)
// with a tuple inequality, so the planner gets an index range scan
// instead of the previous "id → SELECT created_at" subselect.
func EncodeTimeUUID(t time.Time, id uuid.UUID) string {
	raw := t.UTC().Format(time.RFC3339Nano) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeTimeUUID is the inverse. It returns ErrBadRequest on a
// malformed cursor so handlers can pass it straight to WriteError.
func DecodeTimeUUID(cursor string) (time.Time, uuid.UUID, error) {
	if cursor == "" {
		return time.Time{}, uuid.Nil, errors.New("empty cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	return t, id, nil
}
