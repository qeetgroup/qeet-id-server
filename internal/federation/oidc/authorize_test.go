package oidc

import (
	"testing"
)

// TestOfflineAccess checks that any client registered for refresh may ask for
// offline_access, and that a refresh token comes with every grant unless the
// client registered offline_access, which then makes it come only when granted.
func TestOfflineAccess(t *testing.T) {
	renews := []string{"authorization_code", "refresh_token"}
	codeOnly := []string{"authorization_code"}
	standard := []string{"openid", "profile"}
	optedIn := []string{"openid", "profile", "offline_access"}
	for _, tc := range []struct {
		name               string
		scopes, grantTypes []string
		scope              string
		want               bool
	}{
		{"a registered scope", standard, codeOnly, "profile", true},
		{"an unregistered scope", standard, renews, "email", false},
		{"offline_access from a client that renews", standard, renews, "offline_access", true},
		{"offline_access from a client that doesn't", standard, codeOnly, "offline_access", false},
		{"offline_access registered by a client that doesn't renew", optedIn, codeOnly, "offline_access", true},
	} {
		if got := scopePermitted(tc.scopes, tc.grantTypes, tc.scope); got != tc.want {
			t.Errorf("scopePermitted, %s: %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name                        string
		scopes, grantTypes, granted []string
		want                        bool
	}{
		{"no refresh grant", standard, codeOnly, []string{"openid", "offline_access"}, false},
		{"a client that didn't register offline_access, without it", standard, renews, []string{"openid"}, true},
		{"a client that didn't register offline_access, with it", standard, renews, []string{"openid", "offline_access"}, true},
		{"a client that registered offline_access, without it", optedIn, renews, []string{"openid"}, false},
		{"a client that registered offline_access, with it", optedIn, renews, []string{"openid", "offline_access"}, true},
	} {
		if got := issuesRefreshToken(tc.scopes, tc.grantTypes, tc.granted); got != tc.want {
			t.Errorf("issuesRefreshToken, %s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
