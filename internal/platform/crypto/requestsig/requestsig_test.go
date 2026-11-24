package requestsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSignIsHMACSHA256OfTimestampAndBody checks the scheme against an
// independent HMAC-SHA256 of "timestamp.body", lower-case hex, so algorithm,
// encoding and what is signed can't drift, and that each input changes it.
func TestSignIsHMACSHA256OfTimestampAndBody(t *testing.T) {
	body := []byte(`{"event":"user.created","id":"01J"}`)
	mac := hmac.New(sha256.New, []byte("whsec_abc123"))
	mac.Write([]byte("1700000000." + string(body)))
	if got, want := Sign("whsec_abc123", "1700000000", body), hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("Sign = %q, want %q", got, want)
	}
	if got := Sign("s", "1", nil); len(got) != 64 || got != strings.ToLower(got) {
		t.Errorf("Sign of an empty body = %q, want 64 lower-case hex digits", got)
	}
	base := Sign("secret", "1", []byte(`{"a":1}`))
	for name, other := range map[string]string{
		"another secret":    Sign("other", "1", []byte(`{"a":1}`)),
		"another timestamp": Sign("secret", "2", []byte(`{"a":1}`)),
		"another body":      Sign("secret", "1", []byte(`{"a":2}`)),
	} {
		if other == base {
			t.Errorf("%s signs the same", name)
		}
	}
}

// TestVerifyRefusesAStaleTimestamp checks that a request signed outside the
// tolerance, or with no timestamp, fails verification, however well signed,
// and one within it passes.
func TestVerifyRefusesAStaleTimestamp(t *testing.T) {
	body := []byte(`{"user_id":"1"}`)
	now := time.Now()
	for name, c := range map[string]struct {
		sent time.Time
		want error
	}{
		"just now":            {now, nil},
		"four minutes ago":    {now.Add(-4 * time.Minute), nil},
		"an hour ago":         {now.Add(-time.Hour), ErrStale},
		"ten minutes ahead":   {now.Add(10 * time.Minute), ErrStale},
		"a day ago, replayed": {now.Add(-24 * time.Hour), ErrStale},
	} {
		h := http.Header{}
		SetHeaders(h, c.sent, body, "secret")
		if err := Verify(h, body, "secret", now, Tolerance); !errors.Is(err, c.want) {
			t.Errorf("signed %s: %v, want %v", name, err, c.want)
		}
	}
	h := http.Header{}
	SetHeaders(h, now, body, "secret")
	h.Del(TimestampHeader)
	if err := Verify(h, body, "secret", now, Tolerance); !errors.Is(err, ErrStale) {
		t.Errorf("no timestamp: %v, want %v", err, ErrStale)
	}
}

// TestRotatedSecretVerifiesDuringTheOverlap checks that a request signed with
// a new secret and the one it replaced verifies with either, newest first,
// and with no other secret, nor once its body or timestamp is changed.
func TestRotatedSecretVerifiesDuringTheOverlap(t *testing.T) {
	body := []byte(`{"user_id":"1"}`)
	now := time.Now()
	h := http.Header{}
	SetHeaders(h, now, body, "new", "old")
	if got, want := h.Get(SignatureHeader), "sha256="+Sign("new", h.Get(TimestampHeader), body)+",sha256="+Sign("old", h.Get(TimestampHeader), body); got != want {
		t.Errorf("%s = %q, want %q", SignatureHeader, got, want)
	}
	for _, secret := range []string{"new", "old"} {
		if err := Verify(h, body, secret, now, Tolerance); err != nil {
			t.Errorf("verify with the %s secret during the overlap: %v", secret, err)
		}
	}
	if err := Verify(h, body, "another", now, Tolerance); !errors.Is(err, ErrSignature) {
		t.Errorf("verify with another secret: %v, want %v", err, ErrSignature)
	}
	if err := Verify(h, []byte(`{"user_id":"2"}`), "new", now, Tolerance); !errors.Is(err, ErrSignature) {
		t.Errorf("verify a changed body: %v, want %v", err, ErrSignature)
	}
	h.Set(TimestampHeader, strconv.FormatInt(now.Unix()+1, 10))
	if err := Verify(h, body, "new", now, Tolerance); !errors.Is(err, ErrSignature) {
		t.Errorf("verify a changed timestamp: %v, want %v", err, ErrSignature)
	}
}
