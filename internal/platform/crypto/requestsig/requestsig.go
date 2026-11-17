// Package requestsig signs the requests Qeet ID sends to an organization's own
// endpoints, webhook deliveries and auth-hook calls alike, so one receiver's
// check serves both. X-Qeet-Timestamp is the Unix second of sending, and
// X-Qeet-Signature is "sha256=" and the hex HMAC-SHA256, keyed by a secret, of
// the timestamp, a "." and the body: a receiver refuses a stale or replayed
// request as well as a forged one. While a replaced secret overlaps its
// successor the header holds a value for each, comma-separated, newest first.
package requestsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The headers a signed request carries.
const (
	TimestampHeader = "X-Qeet-Timestamp"
	SignatureHeader = "X-Qeet-Signature"
)

// Tolerance is how far a receiver should let a request's timestamp be from
// its own clock.
const Tolerance = 5 * time.Minute

// Sign returns the hex HMAC-SHA256 of timestamp, ".", and body, keyed by
// secret.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SetHeaders stamps h with now and signs body with each of secrets, in order.
func SetHeaders(h http.Header, now time.Time, body []byte, secrets ...string) {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signatures := make([]string, len(secrets))
	for i, secret := range secrets {
		signatures[i] = "sha256=" + Sign(secret, timestamp, body)
	}
	h.Set(TimestampHeader, timestamp)
	h.Set(SignatureHeader, strings.Join(signatures, ","))
}

// Why Verify refuses a request.
var (
	ErrStale     = errors.New("requestsig: timestamp missing or outside the tolerance")
	ErrSignature = errors.New("requestsig: no signature matches the secret")
)

// Verify checks a request as its receiver does: its timestamp is within
// tolerance of now, and one of its signatures is body's under secret.
func Verify(h http.Header, body []byte, secret string, now time.Time, tolerance time.Duration) error {
	timestamp := h.Get(TimestampHeader)
	sent, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || now.Sub(time.Unix(sent, 0)).Abs() > tolerance {
		return ErrStale
	}
	want := []byte("sha256=" + Sign(secret, timestamp, body))
	for _, got := range strings.Split(h.Get(SignatureHeader), ",") {
		if hmac.Equal([]byte(strings.TrimSpace(got)), want) {
			return nil
		}
	}
	return ErrSignature
}
