package secret

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

func testService(t *testing.T, key byte) *Service {
	t.Helper()
	box, err := envelope.New(bytes.Repeat([]byte{key}, 32))
	if err != nil {
		t.Fatalf("envelope.New: %v", err)
	}
	return NewService(nil, box)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := testService(t, 'k')
	organizationID := uuid.New()
	for _, plain := range []string{"", "short", "sk_live_0123456789abcdef", strings.Repeat("x", 4096)} {
		ct, nonce, err := s.encrypt(organizationID, "api-key", plain)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if plain != "" && bytes.Contains(ct, []byte(plain)) {
			t.Error("ciphertext must not contain plaintext")
		}
		got, err := s.decrypt(organizationID, "api-key", ct, nonce)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if got != plain {
			t.Errorf("round-trip mismatch: got %q want %q", got, plain)
		}
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	s := testService(t, 'k')
	organizationID := uuid.New()
	ct, nonce, _ := s.encrypt(organizationID, "api-key", "sk_live_secret_value")
	ct[len(ct)-1] ^= 0xff // flip a byte
	if _, err := s.decrypt(organizationID, "api-key", ct, nonce); err == nil {
		t.Error("GCM must reject tampered ciphertext")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	s1 := testService(t, 'k')
	s2 := testService(t, 'z')
	organizationID := uuid.New()
	ct, nonce, _ := s1.encrypt(organizationID, "api-key", "secret")
	if _, err := s2.decrypt(organizationID, "api-key", ct, nonce); err == nil {
		t.Error("decrypting with the wrong key must fail")
	}
}

func TestDecryptRejectsWrongOrganizationOrName(t *testing.T) {
	s := testService(t, 'k')
	organizationID := uuid.New()
	ct, nonce, _ := s.encrypt(organizationID, "api-key", "secret")
	if _, err := s.decrypt(uuid.New(), "api-key", ct, nonce); err == nil {
		t.Error("ciphertext transplanted to another tenant must fail")
	}
	if _, err := s.decrypt(organizationID, "other", ct, nonce); err == nil {
		t.Error("ciphertext transplanted to another secret must fail")
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
