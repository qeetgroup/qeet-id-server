package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// fixedSecret is a known base32 (no-padding) 20-byte secret so Code is
// deterministic across runs.
const fixedSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestCode_Deterministic(t *testing.T) {
	// The same secret + time must always produce the same 6-digit code.
	at := time.Unix(1_700_000_000, 0).UTC()
	a, err := Code(fixedSecret, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	b, err := Code(fixedSecret, at)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if a != b {
		t.Errorf("Code not deterministic: %q vs %q", a, b)
	}
	if len(a) != digits {
		t.Errorf("code length = %d, want %d", len(a), digits)
	}
	for _, r := range a {
		if r < '0' || r > '9' {
			t.Errorf("code %q has a non-digit", a)
		}
	}
}

func TestCode_StableWithinPeriod(t *testing.T) {
	// Two times in the same 30s window share a counter → identical code.
	base := time.Unix(1_700_000_000, 0).UTC() // 1_700_000_000 % 30 == 20
	start := base.Add(-20 * time.Second)      // window boundary
	c1, _ := Code(fixedSecret, start)
	c2, _ := Code(fixedSecret, start.Add(29*time.Second))
	if c1 != c2 {
		t.Errorf("codes within the same period differ: %q vs %q", c1, c2)
	}
	// One second later crosses into the next period → (almost certainly) differs.
	c3, _ := Code(fixedSecret, start.Add(30*time.Second))
	if c3 == c1 {
		t.Logf("adjacent-window codes collided (1-in-10^6); not a failure")
	}
}

func TestCode_RejectsBadSecret(t *testing.T) {
	if _, err := Code("not!valid!base32", time.Now()); err == nil {
		t.Error("Code must reject a secret that isn't valid base32")
	}
}

func TestVerify_CurrentWindow(t *testing.T) {
	// A code minted for "now" must verify.
	code, err := Code(fixedSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !Verify(fixedSecret, code) {
		t.Error("a fresh code for the current window must verify")
	}
}

func TestVerify_AcceptsAdjacentSkewWindows(t *testing.T) {
	// Verify tolerates ±1 period of clock skew. A code computed for the
	// previous and the next window must both still be accepted.
	now := time.Now().UTC()
	prev, _ := Code(fixedSecret, now.Add(-period*time.Second))
	next, _ := Code(fixedSecret, now.Add(period*time.Second))
	if !Verify(fixedSecret, prev) {
		t.Error("previous-window code must verify (skew tolerance)")
	}
	if !Verify(fixedSecret, next) {
		t.Error("next-window code must verify (skew tolerance)")
	}
}

func TestVerify_RejectsOutOfWindowCode(t *testing.T) {
	// Two periods in the past is outside the ±1 tolerance → rejected.
	now := time.Now().UTC()
	stale, _ := Code(fixedSecret, now.Add(-2*period*time.Second))
	// Guard against the (vanishingly rare) case where the stale code happens
	// to equal one of the three accepted windows.
	cur, _ := Code(fixedSecret, now)
	prev, _ := Code(fixedSecret, now.Add(-period*time.Second))
	next, _ := Code(fixedSecret, now.Add(period*time.Second))
	if stale == cur || stale == prev || stale == next {
		t.Skip("rare code collision across windows; skipping")
	}
	if Verify(fixedSecret, stale) {
		t.Error("a code two periods old must be rejected")
	}
}

func TestVerify_RejectsWrongAndMalformedCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"too short", "123"},
		{"too long", "1234567"},
		{"non-numeric same length", "abcdef"},
		{"obviously wrong", "000000"},
	}
	// Make sure "000000" isn't coincidentally the current code.
	cur, _ := Code(fixedSecret, time.Now().UTC())
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.code == cur {
				t.Skip("test code coincides with the real current code")
			}
			if Verify(fixedSecret, c.code) {
				t.Errorf("Verify accepted an invalid code %q", c.code)
			}
		})
	}
}

func TestVerify_LowercaseSecretStillVerifies(t *testing.T) {
	// Code upper-cases the secret before decoding, so a lower-case stored
	// secret must still verify a code minted from the canonical secret.
	code, _ := Code(fixedSecret, time.Now().UTC())
	if !Verify(strings.ToLower(fixedSecret), code) {
		t.Error("Verify should be case-insensitive about the secret")
	}
}

func TestNewSecret_DecodableAndUnique(t *testing.T) {
	s1, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	s2, _ := NewSecret()
	if s1 == s2 {
		t.Error("NewSecret should not repeat")
	}
	// A fresh secret must be usable by Code.
	if _, err := Code(s1, time.Now()); err != nil {
		t.Errorf("Code rejected a freshly generated secret: %v", err)
	}
}

func TestProvisioningURL_Shape(t *testing.T) {
	raw := ProvisioningURL(fixedSecret, "Qeet ID", "alice@example.com")
	if !strings.HasPrefix(raw, "otpauth://totp/") {
		t.Fatalf("provisioning URL must use the otpauth scheme: %q", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("provisioning URL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("secret") != fixedSecret {
		t.Errorf("secret = %q, want %q", q.Get("secret"), fixedSecret)
	}
	if q.Get("issuer") != "Qeet ID" {
		t.Errorf("issuer = %q, want %q", q.Get("issuer"), "Qeet ID")
	}
	if q.Get("algorithm") != "SHA1" {
		t.Errorf("algorithm = %q, want SHA1", q.Get("algorithm"))
	}
	if q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Errorf("digits/period = %q/%q, want 6/30", q.Get("digits"), q.Get("period"))
	}
	// The issuer:account label must be in the path.
	if !strings.Contains(u.Path, "Qeet ID:alice@example.com") {
		t.Errorf("label not in path: %q", u.Path)
	}
}
