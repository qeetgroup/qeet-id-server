package secret

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// kmsDecrypter is the slice of the KMS client AWSKMSProvider needs. Narrowing it
// to an interface keeps the provider unit-testable with a fake (no AWS calls).
type kmsDecrypter interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// AWSKMSProvider implements KeyProvider by unwrapping the vault data key from a
// KMS-encrypted ciphertext blob. The wrapped DEK is generated once, out-of-band:
//
//	aws kms generate-data-key --key-id <arn> --key-spec AES_256
//
// storing the returned CiphertextBlob (base64) in config / secret manager.
// At startup DataKey calls kms.Decrypt to recover the plaintext key; it never
// leaves memory (secret.Service caches the derived AEAD cipher and discards it).
type AWSKMSProvider struct {
	client     kmsDecrypter
	keyID      string
	wrappedDEK []byte
}

// NewAWSKMSProvider builds a provider using the default AWS credential chain
// (IRSA / instance role / shared config / env). keyID is the KMS key ARN or id;
// wrappedDEK is the raw (base64-decoded) ciphertext blob of the wrapped key.
func NewAWSKMSProvider(ctx context.Context, keyID string, wrappedDEK []byte) (*AWSKMSProvider, error) {
	if keyID == "" {
		return nil, errors.New("secret: KMS key id is required")
	}
	if len(wrappedDEK) == 0 {
		return nil, errors.New("secret: KMS wrapped DEK is required")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("secret: load aws config: %w", err)
	}
	return &AWSKMSProvider{client: kms.NewFromConfig(awsCfg), keyID: keyID, wrappedDEK: wrappedDEK}, nil
}

// DataKey unwraps and validates the data key. AES requires 16/24/32 bytes.
func (p *AWSKMSProvider) DataKey(ctx context.Context) ([]byte, error) {
	out, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: p.wrappedDEK,
		KeyId:          aws.String(p.keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("secret: kms decrypt: %w", err)
	}
	switch len(out.Plaintext) {
	case 16, 24, 32:
		return out.Plaintext, nil
	default:
		return nil, fmt.Errorf("secret: KMS data key must be 16/24/32 bytes, got %d", len(out.Plaintext))
	}
}
