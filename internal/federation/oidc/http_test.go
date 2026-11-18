package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAppendQuery(t *testing.T) {
	cases := []struct {
		name string
		base string
		kv   []string
		want string
	}{
		{"no existing query", "https://rp/cb", []string{"code", "abc"}, "https://rp/cb?code=abc"},
		{"existing query uses &", "https://rp/cb?x=1", []string{"code", "abc"}, "https://rp/cb?x=1&code=abc"},
		{"skips empty values", "https://rp/cb", []string{"code", "abc", "state", ""}, "https://rp/cb?code=abc"},
		{"escapes values", "https://rp/cb", []string{"state", "a b&c"}, "https://rp/cb?state=a+b%26c"},
		{"multiple pairs", "https://rp/cb", []string{"code", "c", "state", "s"}, "https://rp/cb?code=c&state=s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appendQuery(c.base, c.kv...); got != c.want {
				t.Errorf("appendQuery(%q, %v) = %q, want %q", c.base, c.kv, got, c.want)
			}
		})
	}
}

func TestCurrentURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/oauth/authorize?client_id=rp&scope=openid", nil)
	req.Host = "id.test"
	if got := (&Handler{}).currentURL(req); got != "https://id.test/v1/oauth/authorize?client_id=rp&scope=openid" {
		t.Errorf("currentURL = %q", got)
	}
	configured := &Handler{PublicBaseURL: "https://api.id.qeet.in"}
	if got := configured.currentURL(req); got != "https://api.id.qeet.in/v1/oauth/authorize?client_id=rp&scope=openid" {
		t.Errorf("currentURL with PublicBaseURL = %q", got)
	}
}
