// Package password hashes the secrets people choose (passwords, MFA recovery
// codes) with Argon2id, and random machine secrets (API keys, client secrets)
// with SHA-256. After a successful Verify, NeedsRehash says when to store a
// fresh Hash.
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
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/argon2"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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

// ErrHasherBusy is the answer when the hasher is full: every slot is taken and
// as many callers wait as may, or no slot freed up in time. It is
// errs.ErrServerOverloaded, which is answered 503 with Retry-After.
var ErrHasherBusy = errs.ErrServerOverloaded

// Limits bounds password hashing, the server's most expensive work: so many
// hashes run at once (each holding 19 MiB), at most Queue more callers wait
// for a slot, each for at most MaxWait, and any caller beyond is refused.
type Limits struct {
	Concurrency int           // hashes at once; 0: GOMAXPROCS
	Queue       int           // callers waiting for a slot; 0: twice Concurrency
	MaxWait     time.Duration // longest wait for a slot; 0: one second
}

const defaultMaxWait = time.Second // Limits.MaxWait when unset

var rejections = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "password_hasher_rejections_total",
	Help: "Password hashes refused because the hasher was full (queue_full) or no slot freed up in time (timeout).",
}, []string{"reason"})

// limiter holds the slots of a Limits and counts the callers waiting for one.
type limiter struct {
	slots   chan struct{}
	waiting atomic.Int64
	queue   int64
	wait    time.Duration
}

// hasher is the limiter in force; Configure replaces it.
var hasher atomic.Pointer[limiter]

func init() { Configure(Limits{}) }

// Configure sets the hashing limits. The server runs with the defaults, set at
// init; a test may tighten them. A hash already running or waiting keeps the
// limits it started under.
func Configure(l Limits) {
	if l.Concurrency <= 0 {
		l.Concurrency = runtime.GOMAXPROCS(0)
	}
	if l.Queue <= 0 {
		l.Queue = 2 * l.Concurrency
	}
	if l.MaxWait <= 0 {
		l.MaxWait = defaultMaxWait
	}
	hasher.Store(&limiter{slots: make(chan struct{}, l.Concurrency), queue: int64(l.Queue), wait: l.MaxWait})
}

// run does work in a hasher slot. Bounded, it refuses with ErrHasherBusy when
// the queue is full or no slot frees up within the longest wait, and with
// ctx's error once ctx ends; otherwise it waits as long as it takes.
func run(ctx context.Context, bounded bool, work func()) error {
	l := hasher.Load()
	select {
	case l.slots <- struct{}{}:
	default:
		if err := l.await(ctx, bounded); err != nil {
			return err
		}
	}
	defer func() { <-l.slots }()
	work()
	return nil
}

// await waits for a slot of l as run describes.
func (l *limiter) await(ctx context.Context, bounded bool) error {
	if !bounded {
		l.slots <- struct{}{}
		return nil
	}
	if l.waiting.Add(1) > l.queue {
		l.waiting.Add(-1)
		rejections.WithLabelValues("queue_full").Inc()
		return ErrHasherBusy
	}
	defer l.waiting.Add(-1)
	timer := time.NewTimer(l.wait)
	defer timer.Stop()
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-timer.C:
		rejections.WithLabelValues("timeout").Inc()
		return ErrHasherBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FillForTest takes every slot and queue place of the hasher, so a bounded
// hash is refused at once until the returned function frees them.
func FillForTest() (release func()) {
	l := hasher.Load()
	for range cap(l.slots) {
		l.slots <- struct{}{}
	}
	l.waiting.Add(l.queue)
	return func() {
		l.waiting.Add(-l.queue)
		for range cap(l.slots) {
			<-l.slots
		}
	}
}

// argon2IDKey computes the key; tests replace it to observe concurrency.
var argon2IDKey = argon2.IDKey

// Hash returns an Argon2id PHC-encoded hash:
// $argon2id$v=19$m=19456,t=2,p=1$<saltB64>$<hashB64>. When the hasher is full
// it returns ErrHasherBusy.
func Hash(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	var key []byte
	if err := run(context.Background(), true, func() {
		key = argon2IDKey([]byte(plain), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether plain matches the stored Argon2id hash; any other
// encoding matches nothing. It waits for a hasher slot as long as it takes; a
// request should use VerifyWithin.
func Verify(hash, plain string) bool {
	ok, _ := verify(context.Background(), hash, plain, false)
	return ok
}

// VerifyWithin is Verify for a request, which would rather answer "try again"
// than queue behind other hashes: when the hasher is full it returns
// ErrHasherBusy, and ctx's error once ctx ends.
func VerifyWithin(ctx context.Context, hash, plain string) (bool, error) {
	return verify(ctx, hash, plain, true)
}

// NeedsRehash reports whether a stored hash was made with weaker Argon2id
// parameters than the current ones. Call after a successful Verify and, if
// true, store a fresh Hash of the same plaintext.
func NeedsRehash(hash string) bool {
	mem, time, threads, _, _, err := decodeArgon2id(hash)
	if err != nil {
		return true
	}
	return mem < argonMemKiB || time < argonTime || threads != argonThreads
}

func verify(ctx context.Context, hash, plain string, bounded bool) (bool, error) {
	mem, time, threads, salt, want, err := decodeArgon2id(hash)
	if err != nil {
		return false, nil //nolint:nilerr // a malformed hash matches nothing
	}
	var got []byte
	if err := run(ctx, bounded, func() {
		got = argon2IDKey([]byte(plain), salt, time, mem, threads, uint32(len(want))) // #nosec G115 -- stored key length, a few dozen bytes
	}); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func decodeArgon2id(hash string) (mem, time uint32, threads uint8, salt, key []byte, err error) {
	// Expected layout: ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, key].
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
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
