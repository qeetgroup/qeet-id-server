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

func TestCallbackURL(t *testing.T) {
	if got := callbackURL("https://id.example.com"); got != "https://id.example.com/v1/vault/tokens/callback" {
		t.Errorf("callbackURL = %q", got)
	}
}
