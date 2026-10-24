package password

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// Machine secrets — API keys and the secrets of service principals, agents and
// OAuth clients — are random, at least 192 bits, so guessing one is as hard as
// finding a SHA-256 preimage. They are stored as their SHA-256: Argon2id adds
// nothing to such a secret and would cost a sign-in's CPU on every call.
// Passwords and other secrets people choose stay on Argon2id.

const secretPrefix = "sha256$" // marks a machine secret's SHA-256 hash

// HashSecret returns the stored form of a machine secret.
func HashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return secretPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifySecret reports whether raw is the machine secret hash was made from,
// and whether hash is an Argon2id one from before, to replace with
// HashSecret(raw) now that raw is known to be right.
func VerifySecret(hash, raw string) (ok, rehash bool) {
	if strings.HasPrefix(hash, secretPrefix) {
		return subtle.ConstantTimeCompare([]byte(hash), []byte(HashSecret(raw))) == 1, false
	}
	ok = Verify(hash, raw)
	return ok, ok
}
