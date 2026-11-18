package tokenvault

import "testing"

func TestHasVaultScope(t *testing.T) {
	if !hasVaultScope([]string{"vault:read"}, "slack") {
		t.Error("vault:read should grant access to any provider")
	}
	if !hasVaultScope([]string{"vault:slack"}, "slack") {
		t.Error("vault:<provider> should grant access to that provider")
	}
	if hasVaultScope([]string{"vault:github"}, "slack") {
		t.Error("vault:<other provider> must not grant access")
	}
	if hasVaultScope(nil, "slack") {
		t.Error("no scopes must not grant access")
	}
}

func TestHTMLEscape(t *testing.T) {
	got := htmlEscape(`<script>alert("x")</script> & more`)
	want := `&lt;script&gt;alert("x")&lt;/script&gt; &amp; more`
	if got != want {
		t.Errorf("htmlEscape = %q, want %q", got, want)
	}
}
