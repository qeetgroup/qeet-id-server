// Package password hashes and verifies secrets with Argon2id — the modern,
// memory-hard default — while still verifying legacy bcrypt hashes so existing
// credentials keep working. After a successful Verify, call NeedsRehash to
// transparently upgrade a stored hash to current Argon2id parameters.
//
// The same helpers protect user passwords, OIDC/principal client secrets, API
// keys, and MFA recovery codes, so the bcrypt→Argon2id transition is uniform.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters — OWASP "Password Storage" baseline (19 MiB, t=2, p=1).
// Bump these over time; NeedsRehash upgrades older hashes on next use.
const (
	argonMemKiB  uint32 = 19 * 1024 // 19456 KiB ≈ 19 MiB
	argonTime    uint32 = 2
	argonThreads uint8  = 1
	argonSaltLen        = 16
	argonKeyLen  uint32 = 32
)

// Hash returns an Argon2id PHC-encoded hash:
// $argon2id$v=19$m=19456,t=2,p=1$<saltB64>$<hashB64>.
func Hash(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether plain matches the stored hash, transparently handling
// both Argon2id and legacy bcrypt encodings.
func Verify(hash, plain string) bool {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2id(hash, plain)
	case strings.HasPrefix(hash, "$2"): // bcrypt: $2a$ / $2b$ / $2y$
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
	default:
		return false
	}
}

// NeedsRehash reports whether a stored hash should be re-hashed with the
// current Argon2id parameters — true for legacy bcrypt and for Argon2id hashes
// produced with weaker params. Call after a successful Verify and, if true,
// store a fresh Hash of the same plaintext.
func NeedsRehash(hash string) bool {
	if !strings.HasPrefix(hash, "$argon2id$") {
		return true
	}
	mem, time, threads, _, _, err := decodeArgon2id(hash)
	if err != nil {
		return true
	}
	return mem < argonMemKiB || time < argonTime || threads != argonThreads
}

func verifyArgon2id(hash, plain string) bool {
	mem, time, threads, salt, want, err := decodeArgon2id(hash)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plain), salt, time, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeArgon2id(hash string) (mem, time uint32, threads uint8, salt, key []byte, err error) {
	// Expected layout: ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, key].
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("bad argon2id format")
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if version != argon2.Version {
		return 0, 0, 0, nil, nil, errors.New("incompatible argon2 version")
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	return mem, time, threads, salt, key, nil
}
