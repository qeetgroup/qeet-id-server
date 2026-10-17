package mfa

import (
	"strings"
	"testing"
)

// TestPairingCodeIsReadable: a code is ten characters of Crockford base32 in
// two groups, and reads back the same however it is typed.
func TestPairingCodeIsReadable(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		code, err := newPairingCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != pairingCodeLength+1 || code[5] != '-' || strings.ContainsAny(code, "ILOU") {
			t.Fatalf("code %q: want two groups of five, no I, L, O or U", code)
		}
		n := normalizePairingCode(code)
		if n == "" || n != normalizePairingCode(strings.ToLower(strings.ReplaceAll(code, "-", " "))) {
			t.Fatalf("code %q must read the same in any case, with or without its hyphen", code)
		}
		seen[n] = true
	}
	if len(seen) < 199 {
		t.Fatalf("codes repeat: %d distinct of 200", len(seen))
	}
}

// TestPairingCodeNormalisation: letters mistaken for digits read as the
// digits; anything that cannot be a code is rejected.
func TestPairingCodeNormalisation(t *testing.T) {
	for in, want := range map[string]string{
		"ABCDE-FGHJK":   "ABCDEFGHJK",
		"abcde fghjk":   "ABCDEFGHJK",
		"O0IL1-23456":   "00111" + "23456",
		"ABCDE-FGHJ":    "", // too short
		"ABCDE-FGHJKM":  "", // too long
		"ABCDE-FGHJU":   "", // U is not in the alphabet
		"ABCDE_FGHJK":   "", // unknown separator
		"":              "",
		"ÄBCDE-FGHJK":   "",
		"ABCDE--FGHJK ": "ABCDEFGHJK",
	} {
		if got := normalizePairingCode(in); got != want {
			t.Errorf("normalizePairingCode(%q) = %q, want %q", in, got, want)
		}
	}
}
