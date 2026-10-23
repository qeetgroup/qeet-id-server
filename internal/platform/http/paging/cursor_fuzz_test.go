package paging

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fuzzEncodable reports whether t's UTC year fits RFC 3339's four digits.
func fuzzEncodable(t time.Time) bool {
	year := t.UTC().Year()
	return year >= 1 && year <= 9999
}

func fuzzRawCursor(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// FuzzDecodeTimeUUID checks that DecodeTimeUUID never panics on an arbitrary
// cursor, and that any cursor it accepts survives a re-encode.
func FuzzDecodeTimeUUID(f *testing.F) {
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	f.Add(EncodeTimeUUID(time.Date(2026, 5, 26, 12, 0, 0, 123456789, time.UTC), id))
	f.Add(EncodeTimeUUID(time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC), uuid.Nil))
	f.Add(EncodeTimeUUID(time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), id))
	f.Add(EncodeTimeUUID(time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC), id))
	for _, raw := range []string{
		"2026-05-26T12:00:00+05:30|11111111-1111-4111-8111-111111111111",
		"0000-01-01T00:30:00+01:00|11111111-1111-4111-8111-111111111111",
		"9999-12-31T23:30:00-01:00|11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00,5Z|11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00.1234567891Z|11111111-1111-4111-8111-111111111111",
		"2026-05-26T23:59:60Z|11111111-1111-4111-8111-111111111111",
		"2026-05-26t12:00:00z|11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00Z|urn:uuid:11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00Z|{11111111-1111-4111-8111-111111111111}",
		"2026-05-26T12:00:00Z|11111111111141118111111111111111",
		"2026-05-26T12:00:00Z|11111111-1111-4111-8111-111111111111|extra",
		"2026-05-26T12:00:00Z|",
		"|11111111-1111-4111-8111-111111111111",
		"2026-05-26T12:00:00Z",
		"|",
		"",
	} {
		f.Add(fuzzRawCursor(raw))
	}
	f.Add("")
	f.Add("====")
	f.Add("not+base64/url")
	f.Add(base64.URLEncoding.EncodeToString([]byte("2026-05-26T12:00:00Z|11111111-1111-4111-8111-111111111111")))

	f.Fuzz(func(t *testing.T, cursor string) {
		at, id, err := DecodeTimeUUID(cursor)
		if err != nil {
			if !at.IsZero() || id != uuid.Nil {
				t.Fatalf("DecodeTimeUUID(%q) = (%v, %v, %v), want zero values with the error", cursor, at, id, err)
			}
			return
		}
		if !fuzzEncodable(at) {
			return
		}
		again, againID, err := DecodeTimeUUID(EncodeTimeUUID(at, id))
		if err != nil || !again.Equal(at) || againID != id {
			t.Fatalf("re-encoded cursor for (%v, %v) decoded to (%v, %v, %v)", at, id, again, againID, err)
		}
	})
}

// FuzzTimeUUIDRoundTrip checks that EncodeTimeUUID and DecodeTimeUUID
// round-trip any instant with a four-digit year and any UUID.
func FuzzTimeUUIDRoundTrip(f *testing.F) {
	f.Add(int64(1779796800), int64(123456789), []byte("0123456789abcdef"))
	f.Add(int64(0), int64(0), []byte{})
	f.Add(int64(-62135596800), int64(0), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(int64(253402300799), int64(999999999), []byte("short"))
	f.Add(int64(1779796800), int64(-1), []byte("0123456789abcdef-and-more"))
	f.Add(int64(1779796800), int64(2_000_000_000), []byte{1})

	f.Fuzz(func(t *testing.T, sec, nsec int64, raw []byte) {
		at := time.Unix(sec, nsec)
		if !fuzzEncodable(at) {
			t.Skip()
		}
		var id uuid.UUID
		copy(id[:], raw)
		cursor := EncodeTimeUUID(at, id)
		gotAt, gotID, err := DecodeTimeUUID(cursor)
		if err != nil || !gotAt.Equal(at) || gotID != id {
			t.Fatalf("DecodeTimeUUID(EncodeTimeUUID(%v, %v)) = (%v, %v, %v)", at, id, gotAt, gotID, err)
		}
	})
}
