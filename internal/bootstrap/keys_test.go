package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

// TestSecretsCipherKeepsPreviousKeysReadable checks that the cipher seals with
// SECRETS_KEY and opens what a key in SECRETS_PREVIOUS_KEYS sealed.
func TestSecretsCipherKeepsPreviousKeysReadable(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	enc := base64.StdEncoding.EncodeToString
	box, err := SecretsCipher(context.Background(), &config.Config{
		SecretsProvider: "static", SecretsKey: enc(newKey), SecretsPreviousKeysRaw: " " + enc(oldKey) + " ,",
	})
	if err != nil {
		t.Fatal(err)
	}
	old, err := envelope.New(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if ids := box.KeyIDs(); len(ids) != 2 || ids[1] != old.KeyIDs()[0] {
		t.Fatalf("key ids = %v, want the new key then %s", ids, old.KeyIDs()[0])
	}
	tenant := uuid.New()
	ct, nonce, err := old.Seal(tenant, "secret", "name", []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := box.Open(tenant, "secret", "name", ct, nonce); err != nil || string(plain) != "value" {
		t.Errorf("open under the previous key = %q, %v", plain, err)
	}
}

// TestSecretsCipherRefusesBadPreviousKeys checks that a previous key that
// can't be used stops startup with an error naming the variable.
func TestSecretsCipherRefusesBadPreviousKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for name, cfg := range map[string]config.Config{
		"not base64":      {SecretsProvider: "static", SecretsKey: key, SecretsPreviousKeysRaw: "not base64!"},
		"wrong length":    {SecretsProvider: "static", SecretsKey: key, SecretsPreviousKeysRaw: base64.StdEncoding.EncodeToString([]byte("short"))},
		"kms without kms": {SecretsProvider: "static", SecretsKey: key, SecretsPreviousWrappedDEKsRaw: key},
	} {
		_, err := SecretsCipher(context.Background(), &cfg)
		switch {
		case err == nil:
			t.Errorf("%s: accepted", name)
		case name != "wrong length" && !strings.Contains(err.Error(), "SECRETS_PREVIOUS_"):
			t.Errorf("%s: error %q does not name the variable", name, err)
		}
	}
}
