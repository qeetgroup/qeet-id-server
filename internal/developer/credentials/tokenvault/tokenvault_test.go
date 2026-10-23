package tokenvault

import "testing"

func TestExpiresInSeconds(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int64
	}{
		{"number", float64(3600), 3600},
		{"numeric string", "3600", 3600},
		{"empty string", "", 0},
		{"nil", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := oauthTokenResponse{ExpiresIn: c.in}.expiresInSeconds()
			if got != c.want {
				t.Errorf("expiresInSeconds(%v) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestRandomState_UniqueAndNonEmpty(t *testing.T) {
	a, err := randomState()
	if err != nil {
		t.Fatalf("randomState: %v", err)
	}
	b, err := randomState()
	if err != nil {
		t.Fatalf("randomState: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("randomState must not be empty")
	}
	if a == b {
		t.Fatal("randomState must be unique per call")
	}
}

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

func TestCallbackURL(t *testing.T) {
	if got := callbackURL("https://id.example.com"); got != "https://id.example.com/v1/vault/tokens/callback" {
		t.Errorf("callbackURL = %q", got)
	}
}
