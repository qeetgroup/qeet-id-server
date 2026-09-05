//go:build integration

package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// testDataKey is the same 32 bytes testEnvelope uses, so a ProviderConfig built
// here derives the identical envelope cipher.
var testDataKey = []byte("01234567890123456789012345678901")

// TestQeetAIProviderKeyIsBoundToItsTenant covers the residual half of
// QID-AUD-022.
//
// Tenant LLM keys used to be sealed with one process-wide AES-GCM and a nil
// AAD, so the ciphertext carried no statement about which tenant it belonged
// to. Anything able to write the settings table could copy tenant A's
// ciphertext into tenant B's row and the application would decrypt it straight
// into tenant B's inference path — handing B a working key it never paid for
// and never should have seen.
func TestQeetAIProviderKeyIsBoundToItsTenant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	cfg, err := qeetai.NewProviderConfig(ctx, testPool,
		secret.StaticKeyProvider{Key: testDataKey}, qeetai.PlatformProvider{}, egress.DevelopmentPolicy())
	if err != nil {
		t.Fatalf("build provider config: %v", err)
	}

	victim := createTenant(t, ctx, uniqueSlug("qeetai-victim"))
	attacker := createTenant(t, ctx, uniqueSlug("qeetai-attacker"))

	if _, err := cfg.Set(ctx, victim, qeetai.SetProviderInput{
		Provider: "anthropic", Model: "claude-sonnet-4-6", APIKey: "sk-ant-victim-secret", MaxTokens: 1024,
	}); err != nil {
		t.Fatalf("set victim provider: %v", err)
	}
	if _, err := cfg.Set(ctx, attacker, qeetai.SetProviderInput{
		Provider: "anthropic", Model: "claude-sonnet-4-6", APIKey: "sk-ant-attacker-own", MaxTokens: 1024,
	}); err != nil {
		t.Fatalf("set attacker provider: %v", err)
	}

	// Transplant: lift the victim's sealed key into the attacker's row.
	if _, err := testPool.Exec(ctx, `
		UPDATE qeetai.provider_settings AS dst
		SET key_ciphertext = src.key_ciphertext, key_nonce = src.key_nonce
		FROM qeetai.provider_settings AS src
		WHERE dst.tenant_id = $1 AND src.tenant_id = $2
	`, attacker, victim); err != nil {
		t.Fatalf("transplant ciphertext: %v", err)
	}

	// The AAD names the victim's tenant, so authentication must fail under the
	// attacker's context rather than yield the victim's key.
	if _, err := cfg.ProviderFor(ctx, attacker); err == nil {
		t.Fatal("transplanted provider key decrypted for the wrong tenant")
	}

	// The victim's own row is untouched and still works.
	if _, err := cfg.ProviderFor(ctx, victim); err != nil {
		t.Fatalf("victim's own provider key stopped working: %v", err)
	}
}

// TestQeetAILegacyProviderKeyOpensAndReseals covers the migration path: rows
// written before the envelope switch carry no version prefix and must still
// open (same deployment DEK), then be upgraded in place on first read so the
// unbound ciphertext does not linger.
func TestQeetAILegacyProviderKeyOpensAndReseals(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	cfg, err := qeetai.NewProviderConfig(ctx, testPool,
		secret.StaticKeyProvider{Key: testDataKey}, qeetai.PlatformProvider{}, egress.DevelopmentPolicy())
	if err != nil {
		t.Fatalf("build provider config: %v", err)
	}
	tenantID := createTenant(t, ctx, uniqueSlug("qeetai-legacy"))

	// Seal the way the old code did: raw AES-GCM over the deployment key, no AAD.
	legacyCT, legacyNonce := legacySeal(t, testDataKey, "sk-ant-legacy-value")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO qeetai.provider_settings
		    (tenant_id, provider, model, key_ciphertext, key_nonce, enabled)
		VALUES ($1, 'anthropic', 'claude-sonnet-4-6', $2, $3, true)
	`, tenantID, legacyCT, legacyNonce); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	if _, err := cfg.ProviderFor(ctx, tenantID); err != nil {
		t.Fatalf("legacy provider key must still open: %v", err)
	}

	var storedCT []byte
	if err := testPool.QueryRow(ctx,
		`SELECT key_ciphertext FROM qeetai.provider_settings WHERE tenant_id = $1`, tenantID).Scan(&storedCT); err != nil {
		t.Fatalf("read back ciphertext: %v", err)
	}
	if len(storedCT) < 4 || string(storedCT[:4]) != "QEV\x01" {
		t.Error("legacy row was not resealed into context-bound ciphertext on read")
	}
	// And the resealed row must now reject a cross-tenant transplant.
	other := createTenant(t, ctx, uniqueSlug("qeetai-other"))
	if _, err := testPool.Exec(ctx, `
		INSERT INTO qeetai.provider_settings
		    (tenant_id, provider, model, key_ciphertext, key_nonce, enabled)
		SELECT $1, provider, model, key_ciphertext, key_nonce, true
		FROM qeetai.provider_settings WHERE tenant_id = $2
	`, other, tenantID); err != nil {
		t.Fatalf("copy resealed row: %v", err)
	}
	if _, err := cfg.ProviderFor(ctx, other); err == nil {
		t.Error("resealed ciphertext still decrypted under a different tenant")
	}
}

// legacySeal reproduces the pre-envelope encryption exactly: AES-GCM over the
// deployment data key with a random nonce and no additional data.
func legacySeal(t *testing.T, key []byte, plaintext string) (ciphertext, nonce []byte) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return gcm.Seal(nil, nonce, []byte(plaintext), nil), nonce
}
