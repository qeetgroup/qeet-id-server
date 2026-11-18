package main

import (
	"strings"
	"testing"
)

// ZAP splits its option line like a shell, so the bearer token reaches it inside one quoted value.
func TestZAPGetsTheBearerTokenInOneValue(t *testing.T) {
	const token = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln-_w"
	want := "-config 'replacer.full_list(0).replacement=Bearer " + token + "'"
	if got := zapAuth(token); !strings.HasSuffix(got, want) {
		t.Errorf("ZAP options are %q, want them to end %q", got, want)
	}
}

// A token that could end the quoted value, or isn't one word, is refused before a scanner runs.
func TestScanTokenMustBeABearerToken(t *testing.T) {
	for token, want := range map[string]bool{
		"eyJhbGciOiJFUzI1NiJ9.e30.c2ln-_w": true,
		"qk_live_abc123==":                 true,
		"two words":                        false,
		"quote'd":                          false,
		"new\nline":                        false,
		"":                                 false,
	} {
		if got := bearerToken.MatchString(token); got != want {
			t.Errorf("token %q accepted = %v, want %v", token, got, want)
		}
	}
}
