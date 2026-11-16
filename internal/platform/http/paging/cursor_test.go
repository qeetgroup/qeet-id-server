package paging

import (
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
	if body := Page(page, ""); body["next_cursor"] != nil {
		t.Errorf("the last page's body carries next_cursor %v", body["next_cursor"])
	}
	if c, err := ParseCursor(url.Values{}); err != nil || c.Set {
		t.Errorf("no cursor: %+v, %v", c, err)
	}
	if _, err := ParseCursor(url.Values{"cursor": {"not a cursor"}}); err == nil {
		t.Error("a malformed cursor was accepted")
	}
}
