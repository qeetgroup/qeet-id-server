package returnto

import "testing"

func TestValid(t *testing.T) {
	allowed := Origins("https://api.id.example", "https://accounts.id.example/", "not a url")
	for _, tc := range []struct {
		returnTo string
		want     bool
	}{
		{"https://api.id.example/oauth/authorize?client_id=a", true},
		{"HTTPS://API.ID.EXAMPLE/oauth/authorize", true},
		{"/device?user_code=ABCD", true},
		{"", false},
		{"//evil.example/x", false},
		{"https://evil.example/oauth/authorize", false},
		{"https://user:pass@api.id.example/", false},
		{"/a\\b", false},
		{"/a b", false},
		{"javascript:alert(1)", false},
		{"https://api.id.example.evil.example/", false},
	} {
		if got := allowed.Valid(tc.returnTo); got != tc.want {
			t.Errorf("Valid(%q) = %v, want %v", tc.returnTo, got, tc.want)
		}
	}
}
