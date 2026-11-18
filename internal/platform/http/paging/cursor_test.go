package paging

import (
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEncodeDecodeTimeUUID_Roundtrip(t *testing.T) {
	now := time.Date(2026, 5, 26, 12, 0, 0, 123456789, time.UTC)
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	enc := EncodeTimeUUID(now, id)
	if enc == "" {
		t.Fatal("encoded cursor must not be empty")
	}
	gotT, gotID, err := DecodeTimeUUID(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotT.Equal(now) {
		t.Errorf("time: got %v, want %v", gotT, now)
	}
	if gotID != id {
		t.Errorf("uuid: got %v, want %v", gotID, id)
	}
}

func TestDecodeTimeUUID_Errors(t *testing.T) {
	cases := []string{
		"",
		"not-base64!!!",
		// Base64 of "no-pipe-here": still base64 but format wrong.
		"bm8tcGlwZS1oZXJl",
		// Base64 of "2026-05-26T12:00:00Z|not-a-uuid"
		"MjAyNi0wNS0yNlQxMjowMDowMFp8bm90LWEtdXVpZA",
	}
	for _, c := range cases {
		if _, _, err := DecodeTimeUUID(c); err == nil {
			t.Errorf("expected error for cursor %q", c)
		}
	}
}

func TestEncodeTimeUUID_TimezoneNormalised(t *testing.T) {
	// A cursor produced in a non-UTC location must decode to the same
	// instant — the format-string uses .UTC() on encode and parses
	// RFC3339 on decode.
	loc, _ := time.LoadLocation("Asia/Kolkata")
	t1 := time.Date(2026, 5, 26, 17, 30, 0, 0, loc)
	id := uuid.New()
	enc := EncodeTimeUUID(t1, id)
	got, _, _ := DecodeTimeUUID(enc)
	if !got.Equal(t1) {
		t.Errorf("instants must round-trip across timezones; got %v want %v", got, t1)
	}
}

// TestKeysetPage checks a page read with limit+1 is cut to limit with the last
// item's cursor, that a short one has none, and that the cursor reads back.
func TestKeysetPage(t *testing.T) {
	type item struct {
		at time.Time
		id uuid.UUID
	}
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	items := []item{{at, uuid.New()}, {at.Add(-time.Minute), uuid.New()}, {at.Add(-2 * time.Minute), uuid.New()}}
	key := func(i item) (time.Time, uuid.UUID) { return i.at, i.id }

	page, next := Next(items, 2, key)
	if len(page) != 2 || next == "" {
		t.Fatalf("a full page: %d items, next %q", len(page), next)
	}
	c, err := ParseCursor(url.Values{"cursor": {next}})
	if err != nil || !c.Set || !c.Time.Equal(items[1].at) || c.ID != items[1].id {
		t.Fatalf("cursor %+v, %v; want the second item's key", c, err)
	}
	if page, next = Next(items, 3, key); len(page) != 3 || next != "" {
		t.Errorf("the last page: %d items, next %q", len(page), next)
	}
	if c, err := ParseCursor(url.Values{}); err != nil || c.Set {
		t.Errorf("no cursor: %+v, %v", c, err)
	}
	if _, err := ParseCursor(url.Values{"cursor": {"not a cursor"}}); err == nil {
		t.Error("a malformed cursor was accepted")
	}
}

// TestCursorBefore checks that the first page passes NULL for both keyset
// parameters and a later page the cursor's key.
func TestCursorBefore(t *testing.T) {
	if at, id := (Cursor{}).Before(); at != nil || id != nil {
		t.Errorf("first page: %v, %v; want nil, nil", at, id)
	}
	c := Cursor{Set: true, Time: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC), ID: uuid.New()}
	if at, id := c.Before(); at == nil || !at.Equal(c.Time) || id == nil || *id != c.ID {
		t.Errorf("later page: %v, %v; want %v, %v", at, id, c.Time, c.ID)
	}
}

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
