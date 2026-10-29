//go:build integration

package bootstrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope/reseal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

func reencryptCipher(t *testing.T, current []byte, previous ...[]byte) *envelope.Cipher {
	t.Helper()
	box, err := envelope.New(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// sealedTheOldestWay seals plaintext as values were before they were bound
// to a context: AES-GCM under the data key itself.
func sealedTheOldestWay(t *testing.T, key []byte, plaintext string) ([]byte, []byte) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{5}, aead.NonceSize())
	return aead.Seal(nil, nonce, []byte(plaintext), nil), nonce
}

// TestEncryptedColumnsMatchTheSchema runs the re-encryption job's queries
// over every listed column against the migrated schema, so a renamed table or
// column fails here rather than in the job.
func TestEncryptedColumnsMatchTheSchema(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	box := reencryptCipher(t, bytes.Repeat([]byte{1}, 32))
	if _, err := reseal.Count(ctx, pool, box, EncryptedColumns()); err != nil {
		t.Fatalf("count: %v", err)
	}
	if res, err := reseal.Run(ctx, pool, box, EncryptedColumns(), ReencryptBatch, ReencryptBudget); err != nil || !res.Finished {
		t.Fatalf("run = %+v, %v", res, err)
	}
}

// TestRotationKeepsStoredSecretsReadable stores values with the old data key,
// some in the oldest scheme, rotates to a new key, runs the secrets-reencrypt
// job, removes the old key, and checks the services that own the values still
// read them: the job rebuilt each value's context as its owner seals it.
func TestRotationKeepsStoredSecretsReadable(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	before := reencryptCipher(t, oldKey)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)

	sec, err := secret.NewService(pool, before).Create(ctx, tenant, "api-key", "", "secret-value", nil)
	if err != nil {
		t.Fatal(err)
	}
	ct, nonce := sealedTheOldestWay(t, oldKey, "legacy-secret")
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.secrets (tenant_id, name, ciphertext, nonce) VALUES ($1, 'legacy', $2, $3)`,
		tenant, ct, nonce); err != nil {
		t.Fatal(err)
	}

	accessCT, accessNonce, err := before.Seal(tenant, "token-vault-access", person.ID.String()+":github", []byte("access-1"))
	if err != nil {
		t.Fatal(err)
	}
	legacyCT, legacyNonce := sealedTheOldestWay(t, oldKey, "access-legacy")
	for provider, sealed := range map[string][2][]byte{"github": {accessCT, accessNonce}, "gitlab": {legacyCT, legacyNonce}} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO tenant.token_vault_grants (tenant_id, user_id, provider, access_token_ct, access_token_nonce)
			VALUES ($1, $2, $3, $4, $5)`, tenant, person.ID, provider, sealed[0], sealed[1]); err != nil {
			t.Fatal(err)
		}
	}

	keyCT, keyNonce := sealedTheOldestWay(t, oldKey, "sk-ant-legacy")
	if _, err := pool.Exec(ctx, `
		INSERT INTO qeetai.provider_settings (tenant_id, provider, model, key_ciphertext, key_nonce)
		VALUES ($1, 'anthropic', 'model', $2, $3)`, tenant, keyCT, keyNonce); err != nil {
		t.Fatal(err)
	}

	answer := func(box *envelope.Cipher) *httptest.ResponseRecorder {
		h := idempotency.NewStore(pool, box).Middleware([]string{"POST /v1/things"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"shown":"once"}`))
		}))
		r := httptest.NewRequest(http.MethodPost, "/v1/things", strings.NewReader(`{}`))
		r.Header.Set(idempotency.Header, "key-1")
		r = r.WithContext(httpx.WithPrincipal(r.Context(), dbtest.Principal(person.ID, tenant)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	answer(before)

	rotated := reencryptCipher(t, newKey, oldKey)
	var job func() error
	for _, j := range MaintenanceJobs(pool, nil, rotated) {
		if j.Name == "secrets-reencrypt" {
			job = func() error { return j.Run(ctx) }
		}
	}
	if job == nil {
		t.Fatal("no secrets-reencrypt job is scheduled")
	}
	if err := job(); err != nil {
		t.Fatal(err)
	}
	counts, err := reseal.Count(ctx, pool, rotated, EncryptedColumns())
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range counts {
		if n != 0 {
			t.Errorf("%s: %d values left on the old key", EncryptedColumns()[i].Name(), n)
		}
	}

	after := reencryptCipher(t, newKey)
	secrets := secret.NewService(pool, after)
	if _, value, err := secrets.Reveal(ctx, tenant, sec.ID); err != nil || value != "secret-value" {
		t.Errorf("secret = %q, %v", value, err)
	}
	if _, value, err := secrets.GetByName(ctx, tenant, "legacy"); err != nil || value != "legacy-secret" {
		t.Errorf("oldest-scheme secret = %q, %v", value, err)
	}
	vault := tokenvault.NewService(pool, after)
	for provider, want := range map[string]string{"github": "access-1", "gitlab": "access-legacy"} {
		if got, err := vault.GetAccessToken(ctx, tenant, person.ID, provider); err != nil || got != want {
			t.Errorf("%s access token = %q, %v", provider, got, err)
		}
	}
	if _, err := qeetai.NewProviderConfig(pool, after, qeetai.PlatformProvider{}).ProviderFor(ctx, tenant); err != nil {
		t.Errorf("Qeet AI provider key: %v", err)
	}
	if rec := answer(after); rec.Header().Get("Idempotent-Replayed") != "true" || rec.Body.String() != `{"shown":"once"}` {
		t.Errorf("replayed answer: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}
