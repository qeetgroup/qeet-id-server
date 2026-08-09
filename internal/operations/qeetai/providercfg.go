package qeetai

// Per-tenant "bring your own key" (BYOK) AI provider configuration.
//
// The qeetai's model provider used to be a single deployment-level singleton
// built from QEETAI_* env at boot. This file adds a per-tenant seam: an
// organization owner/admin can store their own provider + API key, and the
// qeetai then streams a turn through THEIR provider. When a tenant hasn't
// configured a key, we fall back to the deployment-level platform config, so
// qeetai keeps working out of the box.
//
// The tenant API key is encrypted at rest with AES-256-GCM using the SAME data
// key as the secrets vault (a KeyProvider is injected from the composition
// root). Plaintext keys are never persisted and never returned to the client —
// only a last-4 hint is exposed.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/qeetai/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/anthropic"
	"github.com/qeetgroup/qeet-id-server/internal/platform/ai/openai"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// KeyProvider supplies the AES data-encryption key used to encrypt tenant BYOK
// keys at rest. Structurally identical to the secrets-vault KeyProvider so the
// composition root can pass the same provider without the qeetai importing the
// developer/credentials package.
type KeyProvider interface {
	DataKey(ctx context.Context) ([]byte, error)
}

// ConfigSource identifies which provider config a tenant's qeetai resolves to.
type ConfigSource string

const (
	// SourceNone: neither a tenant key nor a platform key is configured.
	SourceNone ConfigSource = "none"
	// SourcePlatform: no tenant key; using the deployment-level QEETAI_* env.
	SourcePlatform ConfigSource = "platform"
	// SourceTenant: the tenant has configured (BYOK) their own provider + key.
	SourceTenant ConfigSource = "tenant"
)

// supportedProviders is the set of provider identifiers accepted on write.
// "azure" is routed through the OpenAI-compatible client and requires base_url.
var supportedProviders = map[string]bool{"anthropic": true, "openai": true, "azure": true}

// EffectiveConfig is the non-secret view of a tenant's resolved provider. It is
// safe to return to the client: it never carries key material, only a last-4
// hint of the tenant's own key.
type EffectiveConfig struct {
	Source    ConfigSource `json:"source"`
	Provider  string       `json:"provider,omitempty"`
	Model     string       `json:"model,omitempty"`
	BaseURL   string       `json:"base_url,omitempty"`
	MaxTokens int          `json:"max_tokens,omitempty"`
	Last4     string       `json:"last4,omitempty"`
}

// PlatformProvider is the deployment-level (env) fallback provider config used
// when a tenant hasn't configured its own key.
type PlatformProvider struct {
	Provider  string
	APIKey    string
	Model     string
	BaseURL   string
	MaxTokens int
}

func (p PlatformProvider) configured() bool {
	return strings.TrimSpace(p.Provider) != "" && strings.TrimSpace(p.APIKey) != ""
}

// ProviderConfig resolves and manages per-tenant BYOK provider settings. It
// satisfies ProviderResolver (consumed by the orchestrator) and backs the
// admin CRUD endpoints.
type ProviderConfig struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	gcm      cipher.AEAD
	platform PlatformProvider
	// httpClient is used only by Test() for the live key-validation probe.
	httpClient *http.Client
}

// NewProviderConfig builds the service, unwrapping the AES data key from the
// provider once (identical to the secrets vault). The key must be 16/24/32
// bytes (AES-128/192/256).
func NewProviderConfig(ctx context.Context, pool *pgxpool.Pool, kp KeyProvider, platform PlatformProvider) (*ProviderConfig, error) {
	key, err := kp.DataKey(ctx)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &ProviderConfig{
		pool:       pool,
		q:          dbgen.New(pool),
		gcm:        gcm,
		platform:   platform,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// PlatformConfigured reports whether a deployment-level fallback key is set.
func (c *ProviderConfig) PlatformConfigured() bool { return c.platform.configured() }

func (c *ProviderConfig) encrypt(plaintext string) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, c.gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = c.gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nonce, nil
}

func (c *ProviderConfig) decrypt(ciphertext, nonce []byte) (string, error) {
	pt, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// hint returns the last 4 characters of a key, but only when it is long enough
// that doing so doesn't reveal most of the value.
func hint(value string) string {
	r := []rune(value)
	if len(r) < 8 {
		return ""
	}
	return string(r[len(r)-4:])
}

// tenantRow loads the tenant's raw settings row, if any.
func (c *ProviderConfig) tenantRow(ctx context.Context, tenantID uuid.UUID) (dbgen.QeetaiProviderSetting, bool, error) {
	row, err := c.q.GetProviderSettings(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbgen.QeetaiProviderSetting{}, false, nil
	}
	if err != nil {
		return dbgen.QeetaiProviderSetting{}, false, err
	}
	return row, true, nil
}

// Resolve returns the effective (non-secret) provider config for a tenant:
// the tenant's own enabled key if present, else the platform fallback, else
// SourceNone.
func (c *ProviderConfig) Resolve(ctx context.Context, tenantID uuid.UUID) (EffectiveConfig, error) {
	row, ok, err := c.tenantRow(ctx, tenantID)
	if err != nil {
		return EffectiveConfig{}, err
	}
	if ok && row.Enabled {
		return EffectiveConfig{
			Source:    SourceTenant,
			Provider:  row.Provider,
			Model:     row.Model,
			BaseURL:   row.BaseUrl,
			MaxTokens: int(row.MaxTokens),
			Last4:     row.KeyLast4,
		}, nil
	}
	if c.platform.configured() {
		return EffectiveConfig{
			Source:    SourcePlatform,
			Provider:  c.platform.Provider,
			Model:     c.platform.Model,
			BaseURL:   c.platform.BaseURL,
			MaxTokens: c.platform.MaxTokens,
		}, nil
	}
	return EffectiveConfig{Source: SourceNone}, nil
}

// ProviderFor builds the ai.Provider a turn should stream through for a tenant.
// Returns errs.New("qeetai_unconfigured", …) when neither a tenant nor a
// platform key is available.
func (c *ProviderConfig) ProviderFor(ctx context.Context, tenantID uuid.UUID) (ai.Provider, error) {
	row, ok, err := c.tenantRow(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if ok && row.Enabled {
		key, derr := c.decrypt(row.KeyCiphertext, row.KeyNonce)
		if derr != nil {
			return nil, fmt.Errorf("qeetai: decrypt tenant provider key: %w", derr)
		}
		return buildProvider(row.Provider, key, row.BaseUrl, row.Model, int(row.MaxTokens)), nil
	}
	if c.platform.configured() {
		return buildProvider(c.platform.Provider, c.platform.APIKey, c.platform.BaseURL, c.platform.Model, c.platform.MaxTokens), nil
	}
	return nil, errs.New("qeetai_unconfigured", "AI qeetai is not configured for this organization")
}

// buildProvider constructs an ai.Provider for the given provider identifier.
// "azure" is served by the OpenAI-compatible client (the admin supplies the
// Azure endpoint via base_url).
func buildProvider(provider, apiKey, baseURL, model string, maxTokens int) ai.Provider {
	switch strings.ToLower(provider) {
	case "openai", "azure":
		return openai.New(apiKey, baseURL, model, maxTokens, nil)
	default: // "anthropic"
		return anthropic.NewProvider(anthropic.New(apiKey, baseURL, model, maxTokens, nil))
	}
}

// SetProviderInput carries a write to the tenant's provider config. APIKey is
// the plaintext key (encrypted before it touches the DB).
type SetProviderInput struct {
	Provider  string
	Model     string
	APIKey    string
	BaseURL   string
	MaxTokens int
	UpdatedBy uuid.UUID
}

func (in *SetProviderInput) normalize() error {
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.Model = strings.TrimSpace(in.Model)
	in.APIKey = strings.TrimSpace(in.APIKey)
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	if !supportedProviders[in.Provider] {
		return errs.ErrBadRequest.WithDetail("provider must be one of: anthropic, openai, azure")
	}
	if in.APIKey == "" {
		return errs.ErrBadRequest.WithDetail("api_key is required")
	}
	if in.Model == "" {
		return errs.ErrBadRequest.WithDetail("model is required")
	}
	if in.Provider == "azure" && in.BaseURL == "" {
		return errs.ErrBadRequest.WithDetail("base_url is required for the azure provider")
	}
	if in.MaxTokens <= 0 {
		in.MaxTokens = 4096
	}
	if in.MaxTokens > 200000 {
		in.MaxTokens = 200000
	}
	return nil
}

// Set validates and upserts the tenant's provider config, encrypting the key.
// Returns the effective (non-secret) config.
func (c *ProviderConfig) Set(ctx context.Context, tenantID uuid.UUID, in SetProviderInput) (EffectiveConfig, error) {
	if err := in.normalize(); err != nil {
		return EffectiveConfig{}, err
	}
	ct, nonce, err := c.encrypt(in.APIKey)
	if err != nil {
		return EffectiveConfig{}, err
	}
	row, err := c.q.UpsertProviderSettings(ctx, dbgen.UpsertProviderSettingsParams{
		TenantID:      tenantID,
		Provider:      in.Provider,
		Model:         in.Model,
		BaseUrl:       in.BaseURL,
		MaxTokens:     int32(in.MaxTokens),
		KeyCiphertext: ct,
		KeyNonce:      nonce,
		KeyLast4:      hint(in.APIKey),
		Enabled:       true,
		UpdatedBy:     toPgUUID(in.UpdatedBy),
	})
	if err != nil {
		return EffectiveConfig{}, err
	}
	return EffectiveConfig{
		Source:    SourceTenant,
		Provider:  row.Provider,
		Model:     row.Model,
		BaseURL:   row.BaseUrl,
		MaxTokens: int(row.MaxTokens),
		Last4:     row.KeyLast4,
	}, nil
}

// Clear removes the tenant's provider config, reverting it to the platform
// fallback (or unconfigured). Idempotent.
func (c *ProviderConfig) Clear(ctx context.Context, tenantID uuid.UUID) error {
	_, err := c.q.DeleteProviderSettings(ctx, tenantID)
	return err
}

// Test performs a minimal live request against the provider to validate the
// key + endpoint before it is saved. Returns nil on success, or a
// client-facing error describing the failure.
func (c *ProviderConfig) Test(ctx context.Context, in SetProviderInput) error {
	if err := in.normalize(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	switch in.Provider {
	case "openai", "azure":
		return c.probeOpenAI(ctx, in)
	default:
		return c.probeAnthropic(ctx, in)
	}
}

// probeAnthropic issues a 1-token messages call; a 200 (or a model-level 400)
// proves the key authenticates, a 401/403 proves it does not.
func (c *ProviderConfig) probeAnthropic(ctx context.Context, in SetProviderInput) error {
	base := in.BaseURL
	if base == "" {
		base = anthropic.DefaultBaseURL
	}
	body, _ := json.Marshal(map[string]any{
		"model":      in.Model,
		"max_tokens": 1,
		"messages":   []map[string]any{{"role": "user", "content": "ping"}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return errs.ErrBadRequest.WithDetail("invalid base_url")
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", in.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	return c.evalProbe(req, "anthropic")
}

// probeOpenAI lists models (a free, auth-only endpoint) to validate the key.
func (c *ProviderConfig) probeOpenAI(ctx context.Context, in SetProviderInput) error {
	base := in.BaseURL
	if base == "" {
		base = openai.DefaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/models", nil)
	if err != nil {
		return errs.ErrBadRequest.WithDetail("invalid base_url")
	}
	req.Header.Set("authorization", "Bearer "+in.APIKey)
	return c.evalProbe(req, "openai")
}

// evalProbe runs the request and maps the response to a client-facing verdict.
func (c *ProviderConfig) evalProbe(req *http.Request, provider string) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errs.New("qeetai_provider_unreachable", "could not reach the provider endpoint: "+err.Error())
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errs.New("qeetai_provider_key_invalid", "the provider rejected the API key")
	case provider == "anthropic" && resp.StatusCode == http.StatusBadRequest:
		// Anthropic authenticates before validating the body; a 400 here means
		// the key is good but the model/body is off — surface as a model error.
		return errs.New("qeetai_provider_model_invalid", "the key authenticated but the model was rejected — check the model id")
	default:
		snippet := readSnippet(resp.Body)
		return errs.New("qeetai_provider_error", fmt.Sprintf("provider returned %d: %s", resp.StatusCode, snippet))
	}
}

// readSnippet reads a short, safe prefix of an error body for diagnostics.
func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 300))
	return strings.TrimSpace(string(b))
}

// toPgUUID converts a uuid.UUID (uuid.Nil ⇒ NULL) to pgtype.UUID for the
// nullable updated_by column.
func toPgUUID(id uuid.UUID) pgtype.UUID {
	if id == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}
