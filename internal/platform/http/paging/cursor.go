// Package paging encodes and decodes the opaque cursors used for keyset
// pagination over the (created_at, id) sort key.
package paging

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// EncodeTimeUUID returns the cursor for a row at (t, id): base64url of
// "RFC3339Nano|uuid". Queries compare it to (created_at, id) as a tuple, which
// an index range scan serves.
func EncodeTimeUUID(t time.Time, id uuid.UUID) string {
	raw := t.UTC().Format(time.RFC3339Nano) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeTimeUUID reverses EncodeTimeUUID. A malformed cursor returns
// errs.ErrBadRequest; an empty one returns a plain error.
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

// Cursor is where a keyset page starts: after the item at (Time, ID), or at
// the beginning when Set is false.
type Cursor struct {
	Set  bool
	Time time.Time
	ID   uuid.UUID
}

// Before is the cursor as a list query's optional before_ts and before_id
// parameters: both nil (NULL) on the first page.
func (c Cursor) Before() (*time.Time, *uuid.UUID) {
	if !c.Set {
		return nil, nil
	}
	return &c.Time, &c.ID
}

// ParseCursor reads the cursor query parameter: absent is the first page, and
// a malformed one is errs.ErrBadRequest.
func ParseCursor(q url.Values) (Cursor, error) {
	raw := q.Get("cursor")
	if raw == "" {
		return Cursor{}, nil
	}
	t, id, err := DecodeTimeUUID(raw)
	if err != nil {
		return Cursor{}, err
	}
	return Cursor{Set: true, Time: t, ID: id}, nil
}

// Next cuts items, read with limit+1, to limit and returns the next page's
// cursor from the last item's key: empty when there is no next page.
func Next[T any](items []T, limit int, key func(T) (time.Time, uuid.UUID)) ([]T, string) {
	if len(items) <= limit {
		return items, ""
	}
	items = items[:limit]
	t, id := key(items[limit-1])
	return items, EncodeTimeUUID(t, id)
}
