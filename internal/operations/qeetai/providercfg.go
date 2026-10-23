package qeetai

// Per-tenant "bring your own key" (BYOK) provider configuration. A tenant's API
// key is sealed with the deployment data key, bound to that tenant, and never
// returned; only a last-4 hint is. A tenant without a key falls back to the
// deployment's QEETAI_* provider.

import (
	"bytes"
	"context"
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
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// KeyProvider supplies the deployment data key that seals tenant provider keys.
// It matches the secrets vault's KeyProvider, so one implementation serves both.
type KeyProvider interface {
	DataKey(ctx context.Context) ([]byte, error)
}

// ConfigSource identifies which provider config a tenant's qeetai resolves to.
type ConfigSource string

const (
	SourceNone     ConfigSource = "none"     // no tenant or platform key
	SourcePlatform ConfigSource = "platform" // the deployment's QEETAI_* key
	SourceTenant   ConfigSource = "tenant"   // the tenant's own (BYOK) key
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

// ProviderConfig resolves and manages per-tenant BYOK provider settings and
// implements ProviderResolver. A tenant admin chooses base_url, so both HTTP
// clients are bounded by egress: httpClient, with a whole-request timeout, for
// the Test probe, and streamClient for model calls.
type ProviderConfig struct {
	pool         *pgxpool.Pool
	q            *dbgen.Queries
	box          *envelope.Cipher
	platform     PlatformProvider
	egress       *egress.Policy
	httpClient   *http.Client
	streamClient *http.Client
}

const (
	probeTimeout        = 15 * time.Second // a Test probe, start to finish
	streamHeaderTimeout = 30 * time.Second // a model call's response headers
)

// newStreamClient returns an egress-bounded client for streamed model calls.
// The response headers must arrive within headerTimeout; the body then streams
// for as long as the request's context allows, which a whole-request
// http.Client.Timeout would cut short.
func newStreamClient(policy *egress.Policy, headerTimeout time.Duration) *http.Client {
	client := policy.HTTPClient(0)
	if t, ok := client.Transport.(*http.Transport); ok {
		t.ResponseHeaderTimeout = headerTimeout
	}
	return client
}

// NewProviderConfig builds the service, deriving its envelope cipher from the
// deployment data key (identical to the secrets vault).
func NewProviderConfig(ctx context.Context, pool *pgxpool.Pool, kp KeyProvider, platform PlatformProvider, policies ...*egress.Policy) (*ProviderConfig, error) {
	key, err := kp.DataKey(ctx)
	if err != nil {
		return nil, err
	}
	box, err := envelope.New(key)
	if err != nil {
		return nil, err
	}
	policy := egress.PublicPolicy(policies...)
	return &ProviderConfig{
		pool:         pool,
		q:            dbgen.New(pool),
		box:          box,
		platform:     platform,
		egress:       policy,
		httpClient:   policy.HTTPClient(probeTimeout),
		streamClient: newStreamClient(policy, streamHeaderTimeout),
	}, nil
}

// PlatformConfigured reports whether a deployment-level fallback key is set.
func (c *ProviderConfig) PlatformConfigured() bool { return c.platform.configured() }

// qeetaiKeyPurpose and qeetaiKeyResource bind a provider key to its tenant, so
// ciphertext copied into another tenant's row won't decrypt. The resource is
// constant because each tenant has one provider row.
const (
	qeetaiKeyPurpose  = "qeetai-provider"
	qeetaiKeyResource = "api-key"
)

func (c *ProviderConfig) encrypt(tenantID uuid.UUID, plaintext string) (ciphertext, nonce []byte, err error) {
	if c.box == nil {
		return nil, nil, errs.ErrInternalServer.WithDetail("Qeet AI key encryption is unavailable")
	}
	return c.box.Seal(tenantID, qeetaiKeyPurpose, qeetaiKeyResource, []byte(plaintext))
}

// decrypt opens a tenant's provider key. envelope.Open also reads legacy rows
// sealed without the tenant context; ProviderFor then reseals them.
func (c *ProviderConfig) decrypt(tenantID uuid.UUID, ciphertext, nonce []byte) (string, error) {
	if c.box == nil {
		return "", errs.ErrInternalServer.WithDetail("Qeet AI key encryption is unavailable")
	}
	plaintext, err := c.box.Open(tenantID, qeetaiKeyPurpose, qeetaiKeyResource, ciphertext, nonce)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// reseal upgrades a legacy row to context-bound ciphertext. Best-effort: a
// failure here must not break the inference path that just decrypted fine.
func (c *ProviderConfig) reseal(ctx context.Context, tenantID uuid.UUID, plaintext string, existing []byte) {
	if c.box == nil || c.box.IsCurrent(existing) {
		return
	}
	ct, nonce, err := c.encrypt(tenantID, plaintext)
	if err != nil {
		return
	}
	_, _ = c.pool.Exec(ctx, `
		UPDATE qeetai.provider_settings
		SET key_ciphertext = $2, key_nonce = $3
		WHERE tenant_id = $1
	`, tenantID, ct, nonce)
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
// Returns errs.ErrQeetAIUnconfigured when neither a tenant nor a platform key is
// available.
func (c *ProviderConfig) ProviderFor(ctx context.Context, tenantID uuid.UUID) (ai.Provider, error) {
	row, ok, err := c.tenantRow(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if ok && row.Enabled {
		key, derr := c.decrypt(tenantID, row.KeyCiphertext, row.KeyNonce)
		if derr != nil {
			return nil, fmt.Errorf("qeetai: decrypt tenant provider key: %w", derr)
		}
		c.reseal(ctx, tenantID, key, row.KeyCiphertext)
		return c.buildProvider(row.Provider, key, row.BaseUrl, row.Model, int(row.MaxTokens)), nil
	}
	if c.platform.configured() {
		return c.buildProvider(c.platform.Provider, c.platform.APIKey, c.platform.BaseURL, c.platform.Model, c.platform.MaxTokens), nil
	}
	return nil, errs.ErrQeetAIUnconfigured
}

// buildProvider returns the ai.Provider for provider; "azure" uses the
// OpenAI-compatible client with the admin's base_url. The HTTP client is
// egress-bounded, so a tenant's base_url can't reach the internal network.
func (c *ProviderConfig) buildProvider(provider, apiKey, baseURL, model string, maxTokens int) ai.Provider {
	client := c.streamClient
	switch strings.ToLower(provider) {
	case "openai", "azure":
		return openai.New(apiKey, baseURL, model, maxTokens, client)
	default: // "anthropic"
		return anthropic.NewProvider(anthropic.New(apiKey, baseURL, model, maxTokens, client))
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

func (in *SetProviderInput) normalize(policy *egress.Policy) error {
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
	if in.BaseURL != "" {
		if _, err := policy.ValidateHTTPURL(in.BaseURL); err != nil {
			return errs.ErrBadRequest.WithDetail("base_url is not an allowed outbound destination: " + err.Error())
		}
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
	if err := in.normalize(c.egress); err != nil {
		return EffectiveConfig{}, err
	}
	ct, nonce, err := c.encrypt(tenantID, in.APIKey)
	if err != nil {
		return EffectiveConfig{}, err
	}
	row, err := c.q.UpsertProviderSettings(ctx, dbgen.UpsertProviderSettingsParams{
		TenantID:      tenantID,
		Provider:      in.Provider,
		Model:         in.Model,
		BaseUrl:       in.BaseURL,
		MaxTokens:     int32(in.MaxTokens), // #nosec G115 -- clamped to 200000 above
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
	if err := in.normalize(c.egress); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
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
		return errs.ErrQeetAIProviderUnreachable.WithMessage("could not reach the provider endpoint: " + err.Error())
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errs.ErrQeetAIProviderKeyInvalid
	case provider == "anthropic" && resp.StatusCode == http.StatusBadRequest:
		// Anthropic authenticates before validating the body; a 400 here means
		// the key is good but the model/body is off — surface as a model error.
		return errs.ErrQeetAIProviderModelInvalid
	default:
		snippet := readSnippet(resp.Body)
		return errs.ErrQeetAIProviderError.WithMessage(fmt.Sprintf("provider returned %d: %s", resp.StatusCode, snippet))
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
