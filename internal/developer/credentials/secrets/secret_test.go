package secret

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testService(t *testing.T) *Service {
	t.Helper()
	s, err := NewService(context.Background(), nil, StaticKeyProvider{Key: bytes.Repeat([]byte("k"), 32)})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := testService(t)
	tenantID := uuid.New()
	for _, plain := range []string{"", "short", "sk_live_0123456789abcdef", strings.Repeat("x", 4096)} {
		ct, nonce, err := s.encrypt(tenantID, "api-key", plain)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if plain != "" && bytes.Contains(ct, []byte(plain)) {
			t.Error("ciphertext must not contain plaintext")
		}
		got, err := s.decrypt(tenantID, "api-key", ct, nonce)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != plain {
			t.Errorf("round-trip mismatch: got %q want %q", got, plain)
		}
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	s := testService(t)
	tenantID := uuid.New()
	ct, nonce, _ := s.encrypt(tenantID, "api-key", "sk_live_secret_value")
	ct[0] ^= 0xff // flip a byte
	if _, err := s.decrypt(tenantID, "api-key", ct, nonce); err == nil {
		t.Error("GCM must reject tampered ciphertext")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	s1 := testService(t)
	s2, _ := NewService(context.Background(), nil, StaticKeyProvider{Key: bytes.Repeat([]byte("z"), 32)})
	tenantID := uuid.New()
	ct, nonce, _ := s1.encrypt(tenantID, "api-key", "secret")
	if _, err := s2.decrypt(tenantID, "api-key", ct, nonce); err == nil {
		t.Error("decrypting with the wrong key must fail")
	}
}

func TestDecryptRejectsWrongTenantOrName(t *testing.T) {
	s := testService(t)
	tenantID := uuid.New()
	ct, nonce, _ := s.encrypt(tenantID, "api-key", "secret")
	if _, err := s.decrypt(uuid.New(), "api-key", ct, nonce); err == nil {
		t.Error("ciphertext transplanted to another tenant must fail")
	}
	if _, err := s.decrypt(tenantID, "other", ct, nonce); err == nil {
		t.Error("ciphertext transplanted to another secret must fail")
	}
}

func TestNewServiceRejectsBadKeyLength(t *testing.T) {
	if _, err := NewService(context.Background(), nil, StaticKeyProvider{Key: []byte("too-short")}); err == nil {
		t.Error("AES requires 16/24/32-byte keys")
	}
}

func TestHint(t *testing.T) {
	if got := hint("short"); got != "" {
		t.Errorf("short secrets reveal no hint, got %q", got)
	}
	if got := hint("sk_live_abcd1234"); got != "1234" {
		t.Errorf("hint = %q, want 1234", got)
	}
}
