package codes

import (
	"encoding/base64"
	"regexp"
	"testing"
)

// TestHashesAreStable pins the stored forms against known SHA-256 digests, so
// every hash already stored still matches the value it was made from.
func TestHashesAreStable(t *testing.T) {
	if got, want := Hash("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"; got != want {
		t.Errorf(`Hash("abc") = %q, want %q`, got, want)
	}
	if got, want := HashHex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Errorf(`HashHex("abc") = %q, want %q`, got, want)
	}
}

// TestURLToken checks that a token is 32 random bytes, URL-safe, returned with
// its Hash.
func TestURLToken(t *testing.T) {
	raw, hash, err := URLToken()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := base64.RawURLEncoding.DecodeString(raw); err != nil || len(b) != 32 {
		t.Errorf("token %q decodes to %d bytes (%v), want 32", raw, len(b), err)
	}
	if hash != Hash(raw) {
		t.Errorf("hash %q is not Hash(token)", hash)
	}
	if other, _, _ := URLToken(); other == raw {
		t.Error("two tokens are equal")
	}
}

// TestNumeric checks a code's length and digits, and the default length.
func TestNumeric(t *testing.T) {
	for length, want := range map[int]int{6: 6, 8: 8, 0: 6, 13: 6} {
		code, err := Numeric(length)
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(code) || len(code) != want {
			t.Errorf("Numeric(%d) = %q, want %d digits", length, code, want)
		}
	}
}
