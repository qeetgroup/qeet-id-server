package password

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestHash_IsArgon2idAndVerifies(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("new hashes must be argon2id, got %q", h)
	}
	if !Verify(h, "correct horse battery staple") {
		t.Error("Verify must accept the correct password")
	}
	if Verify(h, "wrong password") {
		t.Error("Verify must reject a wrong password")
	}
}

func TestHash_SaltedPerCall(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Error("each Hash must use a fresh salt")
	}
}

func TestVerify_AcceptsLegacyBcrypt(t *testing.T) {
	// A pre-existing bcrypt hash must keep verifying after the switch.
	b, err := bcrypt.GenerateFromPassword([]byte("legacy-secret"), 10)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if !Verify(string(b), "legacy-secret") {
		t.Error("Verify must accept a legacy bcrypt hash")
	}
	if Verify(string(b), "nope") {
		t.Error("Verify must reject a wrong password against a bcrypt hash")
	}
}

func TestNeedsRehash(t *testing.T) {
	// Legacy bcrypt → needs rehash.
	b, _ := bcrypt.GenerateFromPassword([]byte("x"), 10)
	if !NeedsRehash(string(b)) {
		t.Error("bcrypt hash must be flagged for rehash")
	}
	// Fresh argon2id at current params → does not.
	h, _ := Hash("x")
	if NeedsRehash(h) {
		t.Error("current-param argon2id must not need rehash")
	}
	// Weaker-param argon2id → needs rehash.
	weak := "$argon2id$v=19$m=1024,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$3Iaa2pYsFvU0bYV0u0sJ8w"
	if !NeedsRehash(weak) {
		t.Error("weaker-param argon2id must be flagged for rehash")
	}
}

func TestVerify_RejectsGarbage(t *testing.T) {
	if Verify("not-a-hash", "x") {
		t.Error("unknown hash format must not verify")
	}
	if Verify("", "x") {
		t.Error("empty hash must not verify")
	}
}

func TestArgon2idConcurrencyIsBounded(t *testing.T) {
	stored, err := Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	limit := int64(cap(argonSlots))
	var running, peak atomic.Int64
	release := make(chan struct{})
	orig := argon2IDKey
	argon2IDKey = func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		n := running.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		running.Add(-1)
		return make([]byte, keyLen)
	}
	t.Cleanup(func() { argon2IDKey = orig })

	var wg sync.WaitGroup
	for i := range 3 * limit {
		wg.Go(func() {
			if i%2 == 0 {
				_, _ = Hash("pw")
			} else {
				_ = Verify(stored, "pw")
			}
		})
	}
	for deadline := time.Now().Add(5 * time.Second); running.Load() < limit && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // time for any caller past the limit to start
	close(release)
	wg.Wait()
	if got := peak.Load(); got != limit {
		t.Fatalf("peak concurrent Argon2id computations = %d, want %d", got, limit)
	}
}

// TestVerifyWithinGivesUp checks that VerifyWithin stops waiting for a hashing
// slot after argonWait or when its context ends, holding no slot after, and
// verifies normally once one is free.
func TestVerifyWithinGivesUp(t *testing.T) {
	stored, err := Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	orig := argonWait
	argonWait = 20 * time.Millisecond
	t.Cleanup(func() {
		argonWait = orig
		for len(argonSlots) > 0 {
			<-argonSlots
		}
	})
	for range cap(argonSlots) {
		argonSlots <- struct{}{}
	}

	start := time.Now()
	if ok, err := VerifyWithin(context.Background(), stored, "pw"); ok || !errors.Is(err, ErrHasherBusy) {
		t.Errorf("VerifyWithin with every slot taken = %v, %v; want false, ErrHasherBusy", ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := VerifyWithin(ctx, stored, "pw"); ok || !errors.Is(err, context.Canceled) {
		t.Errorf("VerifyWithin with an ended context = %v, %v; want false, context.Canceled", ok, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("gave up after %v, want about argonWait", elapsed)
	}
	if n := len(argonSlots); n != cap(argonSlots) {
		t.Fatalf("%d slots held after giving up, want %d", n, cap(argonSlots))
	}

	for range cap(argonSlots) {
		<-argonSlots
	}
	if ok, err := VerifyWithin(context.Background(), stored, "pw"); !ok || err != nil {
		t.Errorf("VerifyWithin with a free slot = %v, %v; want true", ok, err)
	}
	if ok, err := VerifyWithin(context.Background(), stored, "other"); ok || err != nil {
		t.Errorf("VerifyWithin with a wrong password = %v, %v; want false, nil", ok, err)
	}
	if n := len(argonSlots); n != 0 {
		t.Errorf("%d slots still held after VerifyWithin returned", n)
	}
}
