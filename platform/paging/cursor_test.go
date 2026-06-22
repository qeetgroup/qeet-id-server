package paging

import (
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
