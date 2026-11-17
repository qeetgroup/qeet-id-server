package password

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestVerifySecret checks that a machine secret verifies against its SHA-256
// hash and not another's, and that an Argon2id hash from before verifies once
// and asks to be replaced.
func TestVerifySecret(t *testing.T) {
	ctx := context.Background()
	hash := HashSecret("qk_secret")
	if ok, rehash, err := VerifySecret(ctx, hash, "qk_secret"); !ok || rehash || err != nil {
		t.Errorf("the secret against its hash: ok %v, rehash %v, %v; want ok, no rehash", ok, rehash, err)
	}
	if ok, _, _ := VerifySecret(ctx, hash, "qk_other"); ok {
		t.Error("another secret verified")
	}
	legacy, err := Hash("qk_secret")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, err := VerifySecret(ctx, legacy, "qk_secret"); !ok || !rehash || err != nil {
		t.Errorf("the secret against an Argon2id hash: ok %v, rehash %v, %v; want both", ok, rehash, err)
	}
	if ok, rehash, _ := VerifySecret(ctx, legacy, "qk_other"); ok || rehash {
		t.Errorf("another secret against an Argon2id hash: ok %v, rehash %v; want neither", ok, rehash)
	}
}

// TestLegacySecretVerificationIsBounded checks that a machine secret still
// stored as Argon2id waits for the bounded hasher like a password does: with
// the hasher full it is refused at once with ErrHasherBusy instead of queueing,
// so a flood of wrong secrets can't starve sign-in; a SHA-256 one needs no slot.
func TestLegacySecretVerificationIsBounded(t *testing.T) {
	legacy, err := Hash("qk_secret")
	if err != nil {
		t.Fatal(err)
	}
	release := FillForTest()
	done := make(chan error, 1)
	go func() {
		_, _, err := VerifySecret(context.Background(), legacy, "qk_secret")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrHasherBusy) {
			t.Errorf("verify a legacy secret with the hasher full: %v, want %v", err, ErrHasherBusy)
		}
	case <-time.After(2 * time.Second):
		t.Error("verifying a legacy secret queued for the full hasher instead of being refused")
		release()
		<-done
		return
	}
	if ok, _, err := VerifySecret(context.Background(), HashSecret("qk_secret"), "qk_secret"); !ok || err != nil {
		t.Errorf("a SHA-256 secret with the hasher full: %v, %v; want it verified", ok, err)
	}
	release()
}
