package password

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/bcrypt"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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
	limit := int64(cap(hasher.Load().slots))
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

// rejected reads password_hasher_rejections_total for reason from the registry
// /metrics serves.
func rejected(t *testing.T, reason string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "password_hasher_rejections_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" && l.GetValue() == reason {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// configure sets limits for one test and puts the defaults back after it.
func configure(t *testing.T, l Limits) {
	t.Helper()
	Configure(l)
	t.Cleanup(func() { Configure(Limits{}) })
}

// blockHashing makes every Argon2id computation wait until the returned
// function is called, and reports how many are running.
func blockHashing(t *testing.T) (running *atomic.Int64, release func()) {
	t.Helper()
	running = new(atomic.Int64)
	gate := make(chan struct{})
	orig := argon2IDKey
	argon2IDKey = func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		running.Add(1)
		<-gate
		return make([]byte, keyLen)
	}
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() { release(); argon2IDKey = orig })
	return running, release
}

// TestHasherShedsWhenFull checks that once every slot is taken and the queue
// is full, a hash is refused at once with server.overloaded and counted, while
// the hashes running and waiting all finish.
func TestHasherShedsWhenFull(t *testing.T) {
	stored, err := Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	configure(t, Limits{Concurrency: 2, Queue: 1, MaxWait: time.Minute})
	running, release := blockHashing(t)

	var wg sync.WaitGroup
	results := make(chan error, 3)
	for range 3 {
		wg.Go(func() {
			_, err := Hash("pw")
			results <- err
		})
	}
	l := hasher.Load()
	for deadline := time.Now().Add(5 * time.Second); (running.Load() < 2 || l.waiting.Load() < 1) && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if running.Load() != 2 || l.waiting.Load() != 1 {
		t.Fatalf("%d hashing and %d waiting, want 2 and 1", running.Load(), l.waiting.Load())
	}

	before := rejected(t, "queue_full")
	start := time.Now()
	if _, err := Hash("pw"); !errors.Is(err, errs.ErrServerOverloaded) {
		t.Errorf("Hash with the hasher full: %v, want server.overloaded", err)
	}
	if ok, err := VerifyWithin(context.Background(), stored, "pw"); ok || !errors.Is(err, ErrHasherBusy) {
		t.Errorf("VerifyWithin with the hasher full = %v, %v; want false, ErrHasherBusy", ok, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("refusing took %v, want at once", elapsed)
	}
	if got := rejected(t, "queue_full") - before; got != 2 {
		t.Errorf("counted %v refusals, want 2", got)
	}

	release()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("a hash admitted before the hasher filled: %v", err)
		}
	}
	if n := len(l.slots); n != 0 {
		t.Errorf("%d slots still held", n)
	}
}

// TestVerifyWithinGivesUp checks that VerifyWithin stops waiting for a hashing
// slot after the longest wait or when its context ends, holding no slot after,
// and verifies normally once one is free.
func TestVerifyWithinGivesUp(t *testing.T) {
	stored, err := Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	configure(t, Limits{Concurrency: 1, Queue: 4, MaxWait: 20 * time.Millisecond})
	l := hasher.Load()
	l.slots <- struct{}{}

	before := rejected(t, "timeout")
	start := time.Now()
	if ok, err := VerifyWithin(context.Background(), stored, "pw"); ok || !errors.Is(err, ErrHasherBusy) {
		t.Errorf("VerifyWithin with every slot taken = %v, %v; want false, ErrHasherBusy", ok, err)
	}
	if got := rejected(t, "timeout") - before; got != 1 {
		t.Errorf("counted %v timeouts, want 1", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := VerifyWithin(ctx, stored, "pw"); ok || !errors.Is(err, context.Canceled) {
		t.Errorf("VerifyWithin with an ended context = %v, %v; want false, context.Canceled", ok, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("gave up after %v, want about the longest wait", elapsed)
	}
	if n, w := len(l.slots), l.waiting.Load(); n != 1 || w != 0 {
		t.Fatalf("%d slots held and %d waiting after giving up, want 1 and 0", n, w)
	}

	<-l.slots
	if ok, err := VerifyWithin(context.Background(), stored, "pw"); !ok || err != nil {
		t.Errorf("VerifyWithin with a free slot = %v, %v; want true", ok, err)
	}
	if ok, err := VerifyWithin(context.Background(), stored, "other"); ok || err != nil {
		t.Errorf("VerifyWithin with a wrong password = %v, %v; want false, nil", ok, err)
	}
	if n := len(l.slots); n != 0 {
		t.Errorf("%d slots still held after VerifyWithin returned", n)
	}
}

// TestVerifyWaitsWhenFull checks that Verify, which has no way to say "busy",
// waits for a slot rather than reporting a match failure.
func TestVerifyWaitsWhenFull(t *testing.T) {
	stored, err := Hash("pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	configure(t, Limits{Concurrency: 1, Queue: 1, MaxWait: time.Millisecond})
	release := FillForTest()
	done := make(chan bool)
	go func() { done <- Verify(stored, "pw") }()
	select {
	case <-done:
		t.Fatal("Verify returned while the hasher was full")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if !<-done {
		t.Error("Verify of the right password = false once a slot freed")
	}
}

// TestConfigureDefaults checks the limits an unset field gets.
func TestConfigureDefaults(t *testing.T) {
	configure(t, Limits{})
	l := hasher.Load()
	if cap(l.slots) != runtime.GOMAXPROCS(0) || l.queue != int64(2*runtime.GOMAXPROCS(0)) || l.wait != defaultMaxWait {
		t.Errorf("defaults: %d slots, queue %d, wait %v; want GOMAXPROCS, twice that, %v", cap(l.slots), l.queue, l.wait, defaultMaxWait)
	}
}
