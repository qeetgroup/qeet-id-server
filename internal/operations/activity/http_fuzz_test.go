package activity

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

// FuzzDecodeCursor checks that decodeCursor never panics on an arbitrary cursor.
func FuzzDecodeCursor(f *testing.F) {
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	f.Add(encodeCursor(time.Date(2026, 5, 26, 12, 0, 0, 123456789, time.UTC), id))
	f.Add(encodeCursor(time.Time{}, uuid.Nil))
	for _, raw := range []string{
		"2026-05-26T12:00:00Z:11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00+05:30:11111111-1111-4111-8111-111111111111",
		"2026-05-26:11111111-1111-4111-8111-111111111111",
		"2026:11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00Z:urn:uuid:11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00Z:",
		":11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00Z|11111111-1111-4111-8111-111111111111",
		":",
		"",
	} {
		f.Add(base64.RawURLEncoding.EncodeToString([]byte(raw)))
	}
	f.Add("")
	f.Add("====")
	f.Add("not+base64/url")

	f.Fuzz(func(t *testing.T, cursor string) {
		_, _, _ = decodeCursor(cursor)
	})
}
