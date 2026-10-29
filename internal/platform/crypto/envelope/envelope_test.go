package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

var (
	keyA = []byte("01234567890123456789012345678901")
	keyB = []byte("abcdefghijklmnopqrstuvwxyz012345")
)

func TestCipherBindsTenantPurposeAndResource(t *testing.T) {
	box, err := New(keyA)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	ciphertext, nonce, err := box.Seal(tenantA, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	plain, err := box.Open(tenantA, "secret", "api-key", ciphertext, nonce)
	if err != nil || string(plain) != "value" {
		t.Fatalf("open = %q, %v", plain, err)
	}
	for _, tc := range []struct {
		tenant   uuid.UUID
		purpose  string
		resource string
	}{
		{tenantB, "secret", "api-key"},
		{tenantA, "token", "api-key"},
		{tenantA, "secret", "other"},
	} {
		if _, err := box.Open(tc.tenant, tc.purpose, tc.resource, ciphertext, nonce); err == nil {
			t.Fatalf("ciphertext opened under wrong context: %+v", tc)
		}
	}
}

func TestCipherReadsLegacyAESGCM(t *testing.T) {
	ciphertext, nonce := legacySeal(t, keyA, []byte("legacy"))
	box, err := New(keyA)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	plain, err := box.Open(uuid.New(), "secret", "resource", ciphertext, nonce)
	if err != nil || string(plain) != "legacy" {
		t.Fatalf("legacy open = %q, %v", plain, err)
	}
}

// TestCipherReadsVersion1 opens a value sealed before ciphertexts named their
// key (captured from that code), both while its key is current and after a
// rotation made it a previous key.
func TestCipherReadsVersion1(t *testing.T) {
	tenant := uuid.MustParse("6f1c1f2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f")
	ciphertext := mustHex(t, "5145560128b35f55982a0c18dde54ccb2ad303810ca96ab6bb7a4a83a202b04a34bff505fa186b0a54")
	nonce := mustHex(t, "e1b0eb3f352668ffdf9ffd11")
	current, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := New(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	for name, box := range map[string]*Cipher{"current": current, "previous": rotated} {
		plain, err := box.Open(tenant, "secret", "api-key", ciphertext, nonce)
		if err != nil || string(plain) != "sealed before key ids" {
			t.Errorf("%s: open = %q, %v", name, plain, err)
		}
		if box.IsCurrent(ciphertext) {
			t.Errorf("%s: a version 1 ciphertext reports current", name)
		}
	}
	if _, err := current.Open(tenant, "secret", "other", ciphertext, nonce); err == nil {
		t.Error("version 1 ciphertext opened under the wrong context")
	}
}

// TestSealNamesTheCurrentKey checks that a new ciphertext carries the current
// key's id, and that every Cipher given that key names it the same way.
func TestSealNamesTheCurrentKey(t *testing.T) {
	box, err := New(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _, err := box.Seal(uuid.New(), "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	ids := box.KeyIDs()
	if len(ids) != 2 || len(ids[0]) != 2*KeyIDSize {
		t.Fatalf("KeyIDs = %v, want two %d-byte ids", ids, KeyIDSize)
	}
	want := append([]byte{'Q', 'E', 'V', 2}, mustHex(t, ids[0])...)
	if !bytes.HasPrefix(ciphertext, want) || !bytes.Equal(box.CurrentPrefix(), want) {
		t.Fatalf("ciphertext starts %x, want %x", ciphertext[:len(want)], want)
	}
	if !box.IsCurrent(ciphertext) {
		t.Error("a fresh ciphertext is not current")
	}
	alone, err := New(keyB)
	if err != nil {
		t.Fatal(err)
	}
	if alone.KeyIDs()[0] != ids[0] {
		t.Errorf("key id %s differs from %s for the same key", alone.KeyIDs()[0], ids[0])
	}
}

// TestRotationKeepsPreviousKeysReadable seals under one key, rotates to
// another, and checks the value opens while the old key is configured, is
// reported as not current, and fails clearly once the old key is gone.
func TestRotationKeepsPreviousKeysReadable(t *testing.T) {
	tenant := uuid.New()
	before, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := before.Seal(tenant, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, legacyNonce := legacySeal(t, keyA, []byte("legacy"))

	after, err := New(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := after.Open(tenant, "secret", "api-key", ciphertext, nonce); err != nil || string(plain) != "value" {
		t.Fatalf("open under a previous key = %q, %v", plain, err)
	}
	if plain, err := after.Open(tenant, "secret", "api-key", legacy, legacyNonce); err != nil || string(plain) != "legacy" {
		t.Fatalf("legacy open under a previous key = %q, %v", plain, err)
	}
	if after.IsCurrent(ciphertext) {
		t.Error("a value sealed with a previous key reports current")
	}

	removed, err := New(keyB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = removed.Open(tenant, "secret", "api-key", ciphertext, nonce)
	if !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), before.KeyIDs()[0]) {
		t.Errorf("open after removing its key = %v, want ErrUnknownKey naming %s", err, before.KeyIDs()[0])
	}
	if _, err := removed.Open(tenant, "secret", "api-key", legacy, legacyNonce); err == nil {
		t.Error("legacy value opened after its key was removed")
	}
}

// TestCipherRefusesAMangledKeyID checks that a ciphertext cut off inside its
// key id, or relabelled with another configured key's id, does not open.
func TestCipherRefusesAMangledKeyID(t *testing.T) {
	box, err := New(keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.New()
	ciphertext, nonce, err := box.Seal(tenant, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.Open(tenant, "secret", "api-key", ciphertext[:6], nonce); err == nil {
		t.Error("a ciphertext cut off in its key id opened")
	}
	relabelled := append([]byte{'Q', 'E', 'V', 2}, mustHex(t, box.KeyIDs()[1])...)
	relabelled = append(relabelled, ciphertext[4+KeyIDSize:]...)
	if _, err := box.Open(tenant, "secret", "api-key", relabelled, nonce); err == nil {
		t.Error("a ciphertext relabelled with another key's id opened")
	}
}

// TestNewChecksEveryKey checks that a key of the wrong length is refused,
// current or previous, and a key listed twice is kept once.
func TestNewChecksEveryKey(t *testing.T) {
	if _, err := New([]byte("too-short")); err == nil {
		t.Error("a current key of the wrong length was accepted")
	}
	if _, err := New(keyA, []byte("too-short")); err == nil {
		t.Error("a previous key of the wrong length was accepted")
	}
	box, err := New(keyA, keyA, keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if ids := box.KeyIDs(); len(ids) != 2 {
		t.Errorf("KeyIDs = %v, want each key once", ids)
	}
}

// TestCipherRefusesANonceOfTheWrongLength: a stored nonce that was cut short
// or replaced made the AEAD panic, taking down the request that read it. Open
// now refuses it with an error, for current and legacy ciphertext alike.
func TestCipherRefusesANonceOfTheWrongLength(t *testing.T) {
	box, err := New(keyA, keyB)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	tenant := uuid.New()
	ciphertext, nonce, err := box.Seal(tenant, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	version1 := mustHex(t, "5145560128b35f55982a0c18dde54ccb2ad303810ca96ab6bb7a4a83a202b04a34bff505fa186b0a54")
	for _, bad := range [][]byte{nil, nonce[:4], append(append([]byte(nil), nonce...), 0)} {
		if _, err := box.Open(tenant, "secret", "api-key", ciphertext, bad); err == nil {
			t.Errorf("open with a %d-byte nonce succeeded", len(bad))
		}
		if _, err := box.Open(tenant, "secret", "api-key", version1, bad); err == nil {
			t.Errorf("version 1 open with a %d-byte nonce succeeded", len(bad))
		}
		if _, err := box.Open(tenant, "secret", "api-key", []byte("legacy-ciphertext"), bad); err == nil {
			t.Errorf("legacy open with a %d-byte nonce succeeded", len(bad))
		}
	}
}

// legacySeal seals plaintext the oldest way: AES-GCM under the data key itself.
func legacySeal(t *testing.T, key, plaintext []byte) ([]byte, []byte) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, aead.NonceSize())
	return aead.Seal(nil, nonce, plaintext, nil), nonce
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
