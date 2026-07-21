package secret

import (
	"context"
	"errors"
)

// KeyProvider supplies the vault's AES data-encryption key (DEK) at startup.
// NewService unwraps it once and caches the AEAD cipher.
//
// Two implementations ship: StaticKeyProvider (a key supplied via config /
// secret manager, independent of the JWT secret) and AWSKMSProvider (see
// kms.go), which holds a KMS-wrapped DEK that DataKey unwraps via kms.Decrypt.
// A provider drops in without touching the Service — the sketch below matches
// the real AWSKMSProvider:
//
//	type AWSKMSProvider struct {
//		Client     *kms.Client
//		WrappedDEK []byte // ciphertext blob from kms.GenerateDataKey
//	}
//	func (p AWSKMSProvider) DataKey(ctx context.Context) ([]byte, error) {
//		out, err := p.Client.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: p.WrappedDEK})
//		if err != nil {
//			return nil, err
//		}
//		return out.Plaintext, nil // 16/24/32 bytes
//	}
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
