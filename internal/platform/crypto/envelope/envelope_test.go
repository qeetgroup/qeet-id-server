package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/google/uuid"
)

func TestCipherBindsTenantPurposeAndResource(t *testing.T) {
	box, err := New([]byte("01234567890123456789012345678901"))
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
	key := []byte("01234567890123456789012345678901")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	legacy, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := bytes.Repeat([]byte{7}, legacy.NonceSize())
	ciphertext := legacy.Seal(nil, nonce, []byte("legacy"), nil)

	box, err := New(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	plain, err := box.Open(uuid.New(), "secret", "resource", ciphertext, nonce)
	if err != nil || string(plain) != "legacy" {
		t.Fatalf("legacy open = %q, %v", plain, err)
	}
}
