// Package totp implements TOTP (RFC 6238) with HMAC-SHA1 and 6-digit codes.
// We roll our own to avoid an extra dependency; the algorithm is small.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1 is required by RFC 6238
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	digits = 6
	period = 30
)

// NewSecret returns a fresh 20-byte secret encoded as base32 (no padding).
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ProvisioningURL returns an otpauth:// URI for QR-code rendering.
func ProvisioningURL(secret, issuer, account string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", period))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

// Code computes the TOTP code for the given secret at time t.
func Code(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix() / period) // #nosec G115 -- current time, never before 1970
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(b[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod), nil
}

// Verify reports whether code matches the current 30s window or an adjacent
// one. It does not prevent replay: a code stays valid for about 90s, so callers
// that authenticate with it must use VerifyStep and refuse a step already used
// (RFC 6238 §5.2).
func Verify(secret, code string) bool {
	_, ok := VerifyStep(secret, code)
	return ok
}

// VerifyStep verifies the code and reports WHICH time-step matched, so the
// caller can enforce single use by refusing a step it has already accepted.
// The step is the RFC 6238 counter (Unix seconds / period), which increases
// monotonically and is comparable across the acceptance window.
func VerifyStep(secret, code string) (step int64, ok bool) {
	now := time.Now().UTC()
	for _, skew := range []time.Duration{0, -period * time.Second, period * time.Second} {
		at := now.Add(skew)
		want, err := Code(secret, at)
		if err != nil {
			continue
		}
		if hmacEqual(want, code) {
			return at.Unix() / period, true
		}
	}
	return 0, false
}

func hmacEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := 0; i < len(a); i++ {
		x |= a[i] ^ b[i]
	}
	return x == 0
}
