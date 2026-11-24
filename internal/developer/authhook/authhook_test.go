package authhook

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

// testCipher is a cipher with a fixed test key.
func testCipher(t testing.TB) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// TestNewServiceNeedsACipher checks that the hook service is not built without
// the cipher that opens hook secrets: without it every hook would be skipped,
// failing open.
func TestNewServiceNeedsACipher(t *testing.T) {
	if _, err := NewService(new(pgxpool.Pool), nil); err == nil {
		t.Error("built without a cipher")
	}
	if _, err := NewService(new(pgxpool.Pool), testCipher(t)); err != nil {
		t.Errorf("built with a cipher: %v", err)
	}
}
