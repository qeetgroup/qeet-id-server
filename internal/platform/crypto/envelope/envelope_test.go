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

func TestCipherBindsOrganizationPurposeAndResource(t *testing.T) {
	box, err := New(keyA)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	organizationA, organizationB := uuid.New(), uuid.New()
	ciphertext, nonce, err := box.Seal(organizationA, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	plain, err := box.Open(organizationA, "secret", "api-key", ciphertext, nonce)
	if err != nil || string(plain) != "value" {
		t.Fatalf("open = %q, %v", plain, err)
	}
	for _, tc := range []struct {
		organization uuid.UUID
		purpose      string
		resource     string
	}{
		{organizationB, "secret", "api-key"},
		{organizationA, "token", "api-key"},
		{organizationA, "secret", "other"},
	} {
		if _, err := box.Open(tc.organization, tc.purpose, tc.resource, ciphertext, nonce); err == nil {
			t.Fatalf("ciphertext opened under wrong context: %+v", tc)
		}
	}
}

// TestCipherReadsWhatItSealed opens a value sealed by an earlier build
// (captured from that code), so the scheme's context and key derivation stay
// as stored values need them, both while its key is current and after a
// rotation made it a previous key.
func TestCipherReadsWhatItSealed(t *testing.T) {
	organization := uuid.MustParse("6f1c1f2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f")
	ciphertext := mustHex(t, "51455602ac73cc9080f8a11cb41a12419eb5da496cf0537b73f03e657f1fc5846d16a5460f4833c18f3655ebc287be")
	nonce := mustHex(t, "02263814f9aaa679ac3b2394")
	current, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := New(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	for name, box := range map[string]*Cipher{"current": current, "previous": rotated} {
		plain, err := box.Open(organization, "secret", "api-key", ciphertext, nonce)
		if err != nil || string(plain) != "sealed with key ids" {
			t.Errorf("%s: open = %q, %v", name, plain, err)
		}
	}
	if !current.IsCurrent(ciphertext) || rotated.IsCurrent(ciphertext) {
		t.Error("IsCurrent is wrong for a value sealed with keyA")
	}
	if _, err := current.Open(organization, "secret", "other", ciphertext, nonce); err == nil {
		t.Error("the ciphertext opened under the wrong context")
	}
}

// TestCipherRefusesOlderSchemes checks that ciphertexts of the schemes before
// the current one, which nothing writes, don't open: one without a prefix
// (AES-GCM under the data key itself) and a version 1 one, which names no key
// (captured from that code).
func TestCipherRefusesOlderSchemes(t *testing.T) {
	box, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	unprefixed, unprefixedNonce := legacySeal(t, keyA, []byte("legacy"))
	if _, err := box.Open(uuid.New(), "secret", "resource", unprefixed, unprefixedNonce); err == nil {
		t.Error("a ciphertext without a prefix opened")
	}
	organization := uuid.MustParse("6f1c1f2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f")
	version1 := mustHex(t, "5145560128b35f55982a0c18dde54ccb2ad303810ca96ab6bb7a4a83a202b04a34bff505fa186b0a54")
	if _, err := box.Open(organization, "secret", "api-key", version1, mustHex(t, "e1b0eb3f352668ffdf9ffd11")); err == nil {
		t.Error("a version 1 ciphertext opened")
	}
	if box.IsCurrent(version1) || box.IsCurrent(unprefixed) {
		t.Error("an older scheme's ciphertext reports current")
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
	organization := uuid.New()
	before, err := New(keyA)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := before.Seal(organization, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := New(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := after.Open(organization, "secret", "api-key", ciphertext, nonce); err != nil || string(plain) != "value" {
		t.Fatalf("open under a previous key = %q, %v", plain, err)
	}
	if after.IsCurrent(ciphertext) {
		t.Error("a value sealed with a previous key reports current")
	}

	removed, err := New(keyB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = removed.Open(organization, "secret", "api-key", ciphertext, nonce)
	if !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), before.KeyIDs()[0]) {
		t.Errorf("open after removing its key = %v, want ErrUnknownKey naming %s", err, before.KeyIDs()[0])
	}
}

// TestCipherRefusesAMangledKeyID checks that a ciphertext cut off inside its
// key id, or relabelled with another configured key's id, does not open.
func TestCipherRefusesAMangledKeyID(t *testing.T) {
	box, err := New(keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	organization := uuid.New()
	ciphertext, nonce, err := box.Seal(organization, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.Open(organization, "secret", "api-key", ciphertext[:6], nonce); err == nil {
		t.Error("a ciphertext cut off in its key id opened")
	}
	relabelled := append([]byte{'Q', 'E', 'V', 2}, mustHex(t, box.KeyIDs()[1])...)
	relabelled = append(relabelled, ciphertext[4+KeyIDSize:]...)
	if _, err := box.Open(organization, "secret", "api-key", relabelled, nonce); err == nil {
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
// now refuses it with an error.
func TestCipherRefusesANonceOfTheWrongLength(t *testing.T) {
	box, err := New(keyA, keyB)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	organization := uuid.New()
	ciphertext, nonce, err := box.Seal(organization, "secret", "api-key", []byte("value"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for _, bad := range [][]byte{nil, nonce[:4], append(append([]byte(nil), nonce...), 0)} {
		if _, err := box.Open(organization, "secret", "api-key", ciphertext, bad); err == nil {
			t.Errorf("open with a %d-byte nonce succeeded", len(bad))
		}
	}
}

// legacySeal seals plaintext the oldest way, which Open refuses: AES-GCM under
// the data key itself.
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

// TestMACChecksOnlyWhatItsKeySigned checks that a MAC checks under the key that
// made it, current or previous, and fails for another purpose, message, key or
// an empty MAC.
func TestMACChecksOnlyWhatItsKeySigned(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	signer, err := New(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := New(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(newKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("chain|row|hash")
	keyID, mac := signer.MAC("audit-checkpoint", msg)
	cases := []struct {
		name    string
		c       *Cipher
		purpose string
		msg     []byte
		mac     []byte
		want    bool
	}{
		{"the signing key", signer, "audit-checkpoint", msg, mac, true},
		{"a previous key", rotated, "audit-checkpoint", msg, mac, true},
		{"a cipher without the key", other, "audit-checkpoint", msg, mac, false},
		{"another purpose", signer, "other", msg, mac, false},
		{"another message", signer, "audit-checkpoint", []byte("chain|row|other"), mac, false},
		{"no MAC", signer, "audit-checkpoint", msg, nil, false},
	}
	for _, tc := range cases {
		if got := tc.c.CheckMAC(tc.purpose, keyID, tc.msg, tc.mac); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if newID, _ := rotated.MAC("audit-checkpoint", msg); newID == keyID {
		t.Error("a rotated cipher signs with the previous key")
	}
}
