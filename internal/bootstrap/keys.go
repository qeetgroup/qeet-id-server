package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// keyring is the process's key material: the vault data-key provider, the
// cipher every encrypted column uses, and the token signing keys.
type keyring struct {
	provider    secret.KeyProvider
	cipher      *envelope.Cipher
	signingKeys *tokens.SigningKeyRegistry
	issuer      *tokens.Issuer
}

// loadKeys unwraps the vault data key and loads the signing keys, exiting when
// either can't be loaded.
func loadKeys(rootCtx context.Context, cfg *config.Config, pool *pgxpool.Pool) keyring {
	keyProvider, err := SecretsKeyProvider(rootCtx, cfg)
	if err != nil {
		slog.Error("init secrets key provider", "err", err)
		os.Exit(1)
	}
	dataKey, err := keyProvider.DataKey(rootCtx)
	if err != nil {
		slog.Error("unwrap secrets data key", "err", err)
		os.Exit(1)
	}
	sharedCipher, err := envelope.New(dataKey)
	if err != nil {
		slog.Error("init domain encryption", "err", err)
		os.Exit(1)
	}
	// Keep the unwrapped data key for the process lifetime; every vault and
	// encrypted column derives from it. Rotating a KMS-backed key therefore needs a
	// restart.
	keyProvider = secret.StaticKeyProvider{Key: dataKey}
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
	return keyring{provider: keyProvider, cipher: sharedCipher, signingKeys: signingKeyRegistry, issuer: issuer}
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
