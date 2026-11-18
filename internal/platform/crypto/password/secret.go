package password

import (
	"crypto/subtle"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// Machine secrets (API keys, and the secrets of service principals, agents and OAuth clients) are
// random and at least 192 bits, so they are stored as their SHA-256: Argon2id would add nothing and
// cost a sign-in's CPU on every call. Passwords and other secrets people choose stay on Argon2id.

const secretPrefix = "sha256$" // marks a machine secret's SHA-256 hash

// HashSecret returns the stored form of a machine secret.
func HashSecret(raw string) string { return secretPrefix + codes.Hash(raw) }

// VerifySecret reports whether raw is the machine secret hash was made from by
// HashSecret. Any other hash matches nothing.
func VerifySecret(hash, raw string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(HashSecret(raw))) == 1
}
