package secret

import (
	"context"
	"errors"
)

// KeyProvider supplies the vault's AES data-encryption key (DEK) at startup;
// NewService unwraps it once and caches the AEAD cipher. Two implementations ship:
// StaticKeyProvider (key from config/secret manager) and AWSKMSProvider (kms.go).
type KeyProvider interface {
	DataKey(ctx context.Context) ([]byte, error)
}

// StaticKeyProvider returns a fixed key supplied out-of-band (env / secret
// manager). Must be 16, 24, or 32 bytes (AES-128/192/256).
type StaticKeyProvider struct{ Key []byte }

func (p StaticKeyProvider) DataKey(_ context.Context) ([]byte, error) {
	if len(p.Key) == 0 {
		return nil, errors.New("secret: empty data key")
	}
	return p.Key, nil
}
