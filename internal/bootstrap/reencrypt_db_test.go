//go:build integration

package bootstrap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secret"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhook"
	"github.com/qeetgroup/qeet-id-server/internal/operations/qeetai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope/reseal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
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
// some through their services and some written directly, rotates to a new key,
// runs the secrets-reencrypt job, removes the old key, and checks the services
// that own the values still read them: the job rebuilt each value's context as
// its owner seals it.
func TestRotationKeepsStoredSecretsReadable(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	before := reencryptCipher(t, oldKey)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	system := audit.Actor{Type: "system"}

	sec, err := secret.NewService(pool, before).Create(ctx, organization, "api-key", "", "secret-value", nil, secret.Caller{Actor: system})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secret.NewService(pool, before).Create(ctx, organization, "second", "", "second-value", nil, secret.Caller{Actor: system}); err != nil {
		t.Fatal(err)
	}

	accessCT, accessNonce, err := before.Seal(organization, "token-vault-access", person.ID.String()+":github", []byte("access-1"))
	if err != nil {
		t.Fatal(err)
	}
	otherCT, otherNonce, err := before.Seal(organization, "token-vault-access", person.ID.String()+":gitlab", []byte("access-2"))
	if err != nil {
		t.Fatal(err)
	}
	for provider, sealed := range map[string][2][]byte{"github": {accessCT, accessNonce}, "gitlab": {otherCT, otherNonce}} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO organization.token_vault_grants (organization_id, user_id, provider, access_token_ct, access_token_nonce)
			VALUES ($1, $2, $3, $4, $5)`, organization, person.ID, provider, sealed[0], sealed[1]); err != nil {
			t.Fatal(err)
		}
	}

	keyCT, keyNonce, err := before.Seal(organization, "qeetai-provider", "api-key", []byte("sk-ant-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO qeetai.provider_settings (organization_id, provider, model, key_ciphertext, key_nonce)
		VALUES ($1, 'anthropic', 'model', $2, $3)`, organization, keyCT, keyNonce); err != nil {
		t.Fatal(err)
	}

	answer := func(box *envelope.Cipher) *httptest.ResponseRecorder {
		h := idempotency.NewStore(pool, box).Middleware([]string{"POST /v1/things"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"shown":"once"}`))
		}))
		r := httptest.NewRequest(http.MethodPost, "/v1/things", strings.NewReader(`{}`))
		r.Header.Set(idempotency.Header, "key-1")
		r = r.WithContext(httpx.WithPrincipal(r.Context(), dbtest.Principal(person.ID, organization)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	answer(before)

	rotated := reencryptCipher(t, newKey, oldKey)
	jobs, err := MaintenanceJobs(pool, sessionsignal.New(webhook.NewQueue(pool).EnqueueTx), rotated)
	if err != nil {
		t.Fatal(err)
	}
	var job func() error
	for _, j := range jobs {
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
	if _, value, err := secrets.Reveal(ctx, organization, sec.ID, secret.Caller{Actor: system}); err != nil || value != "secret-value" {
		t.Errorf("secret = %q, %v", value, err)
	}
	if _, value, err := secrets.GetByName(ctx, organization, "second", secret.Caller{Actor: system}); err != nil || value != "second-value" {
		t.Errorf("second secret = %q, %v", value, err)
	}
	vault := tokenvault.NewService(pool, after)
	for provider, want := range map[string]string{"github": "access-1", "gitlab": "access-2"} {
		if got, err := vault.GetAccessToken(ctx, organization, person.ID, provider, system); err != nil || got != want {
			t.Errorf("%s access token = %q, %v", provider, got, err)
		}
	}
	providers, err := qeetai.NewProviderConfig(pool, after, qeetai.PlatformProvider{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providers.ProviderFor(ctx, organization); err != nil {
		t.Errorf("Qeet AI provider key: %v", err)
	}
	if rec := answer(after); rec.Header().Get("Idempotent-Replayed") != "true" || rec.Body.String() != `{"shown":"once"}` {
		t.Errorf("replayed answer: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}
