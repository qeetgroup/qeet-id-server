package returnto

import (
	"net/url"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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

func TestFailed(t *testing.T) {
	const login = "https://accounts.id.example"
	back := "https://api.id.example/oauth/authorize?client_id=a&state=s"
	if got, want := Failed(login, back, errs.ErrSAMLAssertionInvalid), login+"/sign-in?error=sso&return_to="+url.QueryEscape(back); got != want {
		t.Errorf("a provider failure: %s, want %s", got, want)
	}
	if got := Failed(login, back, errs.ErrAuthAccountInactive.WithMessage("x")); !strings.Contains(got, "error=account_inactive") {
		t.Errorf("a suspended account: %s, want error=account_inactive", got)
	}
}
