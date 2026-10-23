// Package password hashes secrets with Argon2id and verifies both Argon2id and
// legacy bcrypt hashes; after a successful Verify, NeedsRehash says when to store
// a fresh Hash. It protects passwords, client secrets, API keys and MFA recovery
// codes alike.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters: the OWASP "Password Storage" baseline (19 MiB, t=2,
// p=1). Raise them over time; NeedsRehash flags hashes made with weaker ones.
const (
	argonMemKiB  uint32 = 19 * 1024
	argonTime    uint32 = 2
	argonThreads uint8  = 1
	argonSaltLen        = 16
	argonKeyLen  uint32 = 32
)

// ErrHasherBusy reports that every Argon2id slot stayed taken for argonWait, so
// a VerifyWithin caller can answer "try again later".
var ErrHasherBusy = errors.New("password hasher busy")

// argonSlots bounds concurrent Argon2id computations, so hashing memory stays
// near cap(argonSlots) × 19 MiB however many requests arrive at once.
var argonSlots = make(chan struct{}, 2*runtime.GOMAXPROCS(0))

const argonWaitLimit = 3 * time.Second // VerifyWithin's longest wait for a slot

// argonWait is argonWaitLimit; tests shorten it.
var argonWait = argonWaitLimit

// argon2IDKey computes the key; tests replace it to observe concurrency.
var argon2IDKey = argon2.IDKey

// keyFunc computes an Argon2id key, waiting for a slot as its caller allows.
type keyFunc func(plain, salt []byte, passes, mem uint32, threads uint8, keyLen uint32) ([]byte, error)

// idKey is argon2.IDKey run while holding one of argonSlots, waiting for one as
// long as it takes.
func idKey(plain, salt []byte, passes, mem uint32, threads uint8, keyLen uint32) ([]byte, error) {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2IDKey(plain, salt, passes, mem, threads, keyLen), nil
}

// idKeyWithin returns idKey that gives up waiting for a slot with
// ErrHasherBusy after argonWait, or with ctx's error once it ends.
func idKeyWithin(ctx context.Context) keyFunc {
	return func(plain, salt []byte, passes, mem uint32, threads uint8, keyLen uint32) ([]byte, error) {
		timer := time.NewTimer(argonWait)
		defer timer.Stop()
		select {
		case argonSlots <- struct{}{}:
		case <-timer.C:
			return nil, ErrHasherBusy
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { <-argonSlots }()
		return argon2IDKey(plain, salt, passes, mem, threads, keyLen), nil
	}
}

// Hash returns an Argon2id PHC-encoded hash:
// $argon2id$v=19$m=19456,t=2,p=1$<saltB64>$<hashB64>.
func Hash(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := idKey([]byte(plain), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether plain matches the stored hash, transparently handling
// both Argon2id and legacy bcrypt encodings.
func Verify(hash, plain string) bool {
	ok, _ := verify(hash, plain, idKey)
	return ok
}

// VerifyWithin is Verify for a caller that would rather answer "try again"
// than queue behind other verifications: it returns ErrHasherBusy if no
// hashing slot frees up within argonWait, or ctx's error once ctx ends.
func VerifyWithin(ctx context.Context, hash, plain string) (bool, error) {
	return verify(hash, plain, idKeyWithin(ctx))
}

func verify(hash, plain string, key keyFunc) (bool, error) {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2id(hash, plain, key)
	case strings.HasPrefix(hash, "$2"): // bcrypt: $2a$ / $2b$ / $2y$
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil, nil
	default:
		return false, nil
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

func verifyArgon2id(hash, plain string, key keyFunc) (bool, error) {
	mem, time, threads, salt, want, err := decodeArgon2id(hash)
	if err != nil {
		return false, nil //nolint:nilerr // a malformed hash matches nothing
	}
	got, err := key([]byte(plain), salt, time, mem, threads, uint32(len(want))) // #nosec G115 -- stored key length, a few dozen bytes
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
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
