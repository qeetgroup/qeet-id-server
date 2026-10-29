package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope/reseal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/idempotency"
)

// keyring is the process's key material: the cipher every encrypted column
// uses, and the token signing keys.
type keyring struct {
	cipher      *envelope.Cipher
	signingKeys *tokens.SigningKeyRegistry
	issuer      *tokens.Issuer
}

// loadKeys unwraps the vault data keys and loads the signing keys, exiting when
// either can't be loaded.
func loadKeys(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool) keyring {
	// The unwrapped data keys are kept for the process lifetime; every encrypted
	// column derives from them, so changing a key needs a restart.
	sharedCipher, err := SecretsCipher(rootCtx, cfg)
	if err != nil {
		slog.Error("init domain encryption", "err", err)
		os.Exit(1)
	}
	ids := sharedCipher.KeyIDs()
	slog.Info("vault data keys loaded", "data_key_id", ids[0], "previous_data_key_ids", ids[1:])
	signingKeyRegistry, err := tokens.NewSigningKeyRegistry(pool, sharedCipher)
	if err != nil {
		slog.Error("init signing key registry", "err", err)
		os.Exit(1)
	}
	if cfg.JWTSigningKey == "" {
		if !cfg.IsDev() {
			slog.Error("JWT_SIGNING_KEY is required outside dev (PEM-encoded EC P-256 private key)")
			os.Exit(1)
		}
		// A workstation with no key uses the database's active one, and makes one
		// only for a database that has none: never a new key per start, which
		// retired the last one and split instances sharing the database.
		generated, err := signingKeyRegistry.EnsureDevelopmentKey(rootCtx)
		if err != nil {
			slog.Error("JWT_SIGNING_KEY unset and the database's active key can't be used; "+
				"set SECRETS_KEY to the vault key it was sealed with, or set JWT_SIGNING_KEY (make dev does)", "err", err)
			os.Exit(1)
		}
		if generated {
			slog.Warn("JWT_SIGNING_KEY unset — generated and activated a development ES256 key (the database had none)")
		} else {
			slog.Warn("JWT_SIGNING_KEY unset — signing with the database's active development key")
		}
	} else if err := signingKeyRegistry.Reconcile(rootCtx, cfg.JWTSigningKey, cfg.JWTRetiredKeys, cfg.JWTActivateSigningKey, cfg.JWTSigningKeyRetireGrace); err != nil {
		// Activation is the operator's call alone (JWT_ACTIVATE_SIGNING_KEY): a
		// configured key never replaces the active one by itself, even when this
		// process's vault key is ephemeral.
		slog.Error("reconcile JWT signing key registry", "err", err)
		os.Exit(1)
	}
	issuer, err := signingKeyRegistry.NewIssuer(rootCtx, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		slog.Error("init token issuer from registry; if the active key was sealed with another vault key, set that SECRETS_KEY, "+
			"or activate the configured key with JWT_ACTIVATE_SIGNING_KEY=true", "err", err)
		os.Exit(1)
	}
	slog.Info("JWT signing key registry ready", "active_kid", issuer.KID())
	return keyring{cipher: sharedCipher, signingKeys: signingKeyRegistry, issuer: issuer}
}

// SecretsCipher returns the cipher every encrypted column uses. It seals with
// the data key SecretsKeyProvider supplies and also opens what the previous
// keys sealed: SECRETS_PREVIOUS_KEYS, and SECRETS_PREVIOUS_WRAPPED_DEKS
// unwrapped with KMS.
func SecretsCipher(ctx context.Context, cfg *config.Config) (*envelope.Cipher, error) {
	provider, err := SecretsKeyProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	current, err := provider.DataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("unwrap secrets data key: %w", err)
	}
	var previous [][]byte
	for i, raw := range cfg.SecretsPreviousKeys() {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("SECRETS_PREVIOUS_KEYS entry %d must be base64: %w", i+1, err)
		}
		previous = append(previous, key)
	}
	wrapped := cfg.SecretsPreviousWrappedDEKs()
	if len(wrapped) > 0 && cfg.SecretsProvider != "aws-kms" {
		return nil, errors.New("SECRETS_PREVIOUS_WRAPPED_DEKS needs SECRETS_PROVIDER=aws-kms")
	}
	for i, raw := range wrapped {
		blob, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("SECRETS_PREVIOUS_WRAPPED_DEKS entry %d must be base64: %w", i+1, err)
		}
		kms, err := secret.NewAWSKMSProvider(ctx, cfg.KMSKeyID, blob)
		if err != nil {
			return nil, err
		}
		key, err := kms.DataKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("unwrap SECRETS_PREVIOUS_WRAPPED_DEKS entry %d: %w", i+1, err)
		}
		previous = append(previous, key)
	}
	return envelope.New(current, previous...)
}

// ReencryptBatch is how many rows the secrets-reencrypt job reads at a time,
// and ReencryptBudget how long one run may go on before the next carries on.
const (
	ReencryptBatch  = 200
	ReencryptBudget = 5 * time.Minute
)

// EncryptedColumns are every column sealed with the shared cipher, and the
// context each row was sealed with: what the secrets-reencrypt job moves to
// the current key and envelope_rows_on_old_keys counts. A column added to the
// schema belongs here, with the context its code seals with.
func EncryptedColumns() []reseal.Column {
	byID := func(table, ciphertext, nonce, purpose string) reseal.Column {
		return reseal.Column{Table: table, Key: []string{"id"}, Ciphertext: ciphertext, Nonce: nonce,
			Tenant: "tenant_id", Purpose: purpose, Resource: "id"}
	}
	grant := func(ciphertext, nonce, purpose string) reseal.Column {
		return reseal.Column{Table: "tenant.token_vault_grants", Key: []string{"id"}, Ciphertext: ciphertext, Nonce: nonce,
			Tenant: "tenant_id", Purpose: purpose, Resource: "user_id::text || ':' || provider"}
	}
	totp := func(ciphertext, nonce string) reseal.Column {
		return reseal.Column{Table: "auth.mfa_totp", Key: []string{"user_id"}, Ciphertext: ciphertext, Nonce: nonce,
			Tenant: "user_id", Purpose: "mfa-totp", Resource: "user_id"}
	}
	return []reseal.Column{
		{Table: "tenant.secrets", Key: []string{"id"}, Ciphertext: "ciphertext", Nonce: "nonce",
			Tenant: "tenant_id", Purpose: "secret", Resource: "name"},
		grant("access_token_ct", "access_token_nonce", "token-vault-access"),
		grant("refresh_token_ct", "refresh_token_nonce", "token-vault-refresh"),
		{Table: "tenant.token_vault_providers", Key: []string{"id"}, Ciphertext: "client_secret_ct", Nonce: "client_secret_nonce",
			Tenant: "tenant_id", Purpose: "token-vault-provider", Resource: "provider"},
		{Table: "tenant.social_providers", Key: []string{"id"}, Ciphertext: "client_secret_ct", Nonce: "client_secret_nonce",
			Tenant: "tenant_id", Purpose: "social-provider", Resource: "provider"},
		byID("tenant.webhook_subscriptions", "secret_ct", "secret_nonce", "webhook-signing"),
		byID("tenant.webhook_subscriptions", "previous_secret_ct", "previous_secret_nonce", "webhook-signing"),
		byID("tenant.auth_hooks", "secret_ct", "secret_nonce", "auth-hook-signing"),
		byID("tenant.ldap_connections", "bind_password_ct", "bind_password_nonce", "ldap-bind"),
		byID("tenant.log_sinks", "token_ct", "token_nonce", "siem-token"),
		byID("tenant.oidc_connections", "client_secret_ct", "client_secret_nonce", "oidc-connection"),
		{Table: "tenant.saml_connection_keys", Key: []string{"connection_id"}, Ciphertext: "key_ct", Nonce: "key_nonce",
			Tenant: "tenant_id", Purpose: "saml-sp-key", Resource: "connection_id"},
		{Table: "qeetai.provider_settings", Key: []string{"tenant_id"}, Ciphertext: "key_ciphertext", Nonce: "key_nonce",
			Tenant: "tenant_id", Purpose: "qeetai-provider", Resource: "'api-key'"},
		totp("secret_ct", "secret_nonce"),
		totp("pending_secret_ct", "pending_secret_nonce"),
		{Table: "auth.mfa_push_devices", Key: []string{"id"}, Ciphertext: "push_token_ct", Nonce: "push_token_nonce",
			Tenant: "user_id", Purpose: "mfa-push-token", Resource: "push_token_hash"},
		// A kept rotation is sealed under its session, as a session may have no tenant.
		{Table: "auth.refresh_tokens", Key: []string{"id"}, Ciphertext: "replacement_enc", Nonce: "replacement_nonce",
			Tenant: "session_id", Purpose: "refresh-token-retry", Resource: "id"},
		{Table: "platform.idempotency_keys", Key: []string{"scope", "key"}, Ciphertext: "body_enc", Nonce: "body_nonce",
			Tenant: "scope", TenantOf: idempotency.SealedAs, Purpose: "idempotency", Resource: "scope || '|' || key"},
		// The signing key registry's copy of each private key, sealed under its
		// fixed namespace; re-sealing leaves the signing key itself unchanged.
		{Table: "platform.jwt_signing_keys", Key: []string{"kid"}, Ciphertext: "private_key_ct", Nonce: "private_key_nonce",
			Tenant: "'00000000-0000-5000-8000-000000000017'", Purpose: "jwt-signing-key", Resource: "kid"},
	}
}

// SecretsKeyProvider returns the vault data-key provider selected by
// SECRETS_PROVIDER: "static" decodes SECRETS_KEY (or generates an ephemeral key
// in dev), and "aws-kms" unwraps the key with AWS KMS at startup.
func SecretsKeyProvider(ctx context.Context, cfg *config.Config) (secret.KeyProvider, error) {
	switch cfg.SecretsProvider {
	case "aws-kms":
		blob, err := base64.StdEncoding.DecodeString(cfg.SecretsWrappedDEK)
		if err != nil {
			return nil, fmt.Errorf("SECRETS_WRAPPED_DEK must be base64: %w", err)
		}
		slog.Info("secrets vault key via AWS KMS", "key_id", cfg.KMSKeyID)
		return secret.NewAWSKMSProvider(ctx, cfg.KMSKeyID, blob)
	case "", "static":
		if cfg.SecretsKey != "" {
			key, err := base64.StdEncoding.DecodeString(cfg.SecretsKey)
			if err != nil {
				return nil, fmt.Errorf("SECRETS_KEY must be base64: %w", err)
			}
			return secret.StaticKeyProvider{Key: key}, nil
		}
		// Reached only in dev — Validate() requires SECRETS_KEY otherwise.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate ephemeral secrets key: %w", err)
		}
		slog.Warn("SECRETS_KEY unset — generated an ephemeral vault key; stored secrets will not survive a restart (dev only)")
		return secret.StaticKeyProvider{Key: key}, nil
	default:
		return nil, fmt.Errorf("unknown SECRETS_PROVIDER %q (want \"static\" or \"aws-kms\")", cfg.SecretsProvider)
	}
}
