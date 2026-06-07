package password

import "testing"

func TestWeakReason_RejectsWeak(t *testing.T) {
	weak := []struct{ pw, email string }{
		{"password", ""},
		{"Password", ""},                       // case-insensitive denylist
		{"12345678", ""},                       // sequential
		{"87654321", ""},                       // descending sequential
		{"aaaaaaaa", ""},                       // uniform
		{"qwerty123", ""},                      // denylist
		{"alice@acme.test", "alice@acme.test"}, // equals email
		{"alice", "alice@acme.test"},           // equals email local part
	}
	for _, tc := range weak {
		if WeakReason(tc.pw, tc.email) == "" {
			t.Errorf("WeakReason(%q, %q) = \"\"; want a rejection reason", tc.pw, tc.email)
		}
	}
}

func TestWeakReason_AllowsStrong(t *testing.T) {
	strong := []string{
		"Tr0ub4dour&3",
		"correct-horse-battery-staple",
		"qX7$mN2!pLwz",
		"NewPassw0rd!",
	}
	for _, pw := range strong {
		if r := WeakReason(pw, "alice@acme.test"); r != "" {
			t.Errorf("WeakReason(%q) = %q; want \"\" (accepted)", pw, r)
		}
	}
}
