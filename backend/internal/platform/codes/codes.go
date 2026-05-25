// Package codes generates short numeric codes (for OTP-by-email) and
// long random URL-safe tokens (for password-reset and magic links).
package codes

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

// URLToken returns a 32-byte URL-safe token and its SHA-256 hash.
func URLToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	return raw, Hash(raw), nil
}

func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
