package password

import (
	"crypto/subtle"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// Machine secrets — API keys and the secrets of service principals, agents and
// OAuth clients — are random, at least 192 bits, so guessing one is as hard as
// finding a SHA-256 preimage. They are stored as their SHA-256: Argon2id adds
// nothing to such a secret and would cost a sign-in's CPU on every call.
// Passwords and other secrets people choose stay on Argon2id.

const secretPrefix = "sha256$" // marks a machine secret's SHA-256 hash

// HashSecret returns the stored form of a machine secret.
func HashSecret(raw string) string { return secretPrefix + codes.Hash(raw) }

// VerifySecret reports whether raw is the machine secret hash was made from by
// HashSecret. Any other hash matches nothing.
func VerifySecret(hash, raw string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(HashSecret(raw))) == 1
}
