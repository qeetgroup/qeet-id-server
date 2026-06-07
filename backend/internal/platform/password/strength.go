package password

import "strings"

// commonPasswords is a small, offline denylist of the most frequently breached
// passwords (drawn from public "top passwords" lists). It is intentionally
// lightweight — the authoritative check is the HIBP k-anonymity lookup wired in
// via BREACHED_PASSWORD_CHECK — but this baseline runs everywhere, with no
// network, so obvious choices like "password" or "12345678" are rejected even
// in dev or during a HIBP outage. Entries are compared case-insensitively.
var commonPasswords = map[string]struct{}{}

func init() {
	for _, p := range []string{
		"password", "password1", "password123", "passw0rd", "p@ssw0rd", "p@ssword",
		"12345678", "123456789", "1234567890", "123123123", "11111111", "00000000",
		"qwerty", "qwerty123", "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
		"abc12345", "a1b2c3d4", "iloveyou", "sunshine", "princess", "football",
		"baseball", "welcome", "welcome1", "admin", "admin123", "administrator",
		"letmein", "monkey", "dragon", "master", "shadow", "superman", "batman",
		"trustno1", "whatever", "starwars", "computer", "michael", "jennifer",
		"changeme", "secret", "default", "test1234", "login", "guest", "root",
		"qeetid", "qeet1234",
	} {
		commonPasswords[p] = struct{}{}
	}
}

// WeakReason returns a human-facing reason if plain is an obviously weak
// password, or "" if it passes the baseline checks. It catches common breached
// passwords, passwords equal to the account email (or its local part), and
// trivially uniform/sequential strings. email may be empty.
//
// This is a baseline only: callers that want full breach coverage should also
// run the HIBP checker (see hibp.Checker). Length is enforced separately by the
// request validators (min=8); this function does not re-check it.
func WeakReason(plain, email string) string {
	lower := strings.ToLower(strings.TrimSpace(plain))

	if _, ok := commonPasswords[lower]; ok {
		return "This password is too common. Choose something harder to guess."
	}
	if email != "" {
		em := strings.ToLower(strings.TrimSpace(email))
		local := em
		if at := strings.IndexByte(em, '@'); at > 0 {
			local = em[:at]
		}
		if lower == em || (local != "" && lower == local) {
			return "Your password must not be the same as your email address."
		}
	}
	if isUniform(lower) {
		return "This password is too simple. Choose something harder to guess."
	}
	if isSequential(lower) {
		return "This password is too predictable. Avoid sequences like 12345678 or abcdefg."
	}
	return ""
}

// isUniform reports whether s is a single character repeated (e.g. "aaaaaaaa").
func isUniform(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// isSequential reports whether s is a run of consecutive ascending or
// descending characters (e.g. "12345678", "abcdefgh", "87654321").
func isSequential(s string) bool {
	if len(s) < 4 {
		return false
	}
	asc, desc := true, true
	for i := 1; i < len(s); i++ {
		switch s[i] - s[i-1] {
		case 1:
			desc = false
		case 0xff: // -1 in byte arithmetic
			asc = false
		default:
			return false
		}
	}
	return asc || desc
}
