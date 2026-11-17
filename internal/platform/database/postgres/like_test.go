package postgres

import "testing"

func TestEscapeLike(t *testing.T) {
	for in, want := range map[string]string{
		"plain":   "plain",
		"a_b":     `a\_b`,
		"100%":    `100\%`,
		`c:\path`: `c:\\path`,
		`\%_`:     `\\\%\_`,
		"":        "",
	} {
		if got := EscapeLike(in); got != want {
			t.Errorf("EscapeLike(%q) = %q, want %q", in, got, want)
		}
	}
}
