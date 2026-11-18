// Package codes makes the random one-time values the server hands out and
// keeps only hashed: short numeric codes (email and SMS sign-in codes) and
// long URL-safe tokens (reset and magic links, refresh tokens, secrets).
package codes

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Numeric returns a zero-padded numeric code of the given length.
func Numeric(length int) (string, error) {
	if length <= 0 || length > 12 {
		length = 6
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint64(b[:])
	mod := uint64(1)
	for i := 0; i < length; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", length, n%mod), nil
}

// URLToken returns a 32-byte URL-safe token and its Hash.
func URLToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	return raw, Hash(raw), nil
}

// Hash returns the form a code or token is stored as: its SHA-256, base64url.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// HashHex is Hash in hex, the form the push-MFA tables store.
func HashHex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
