# platform/security/kms

AWS KMS and envelope-encryption client.

Wraps `github.com/aws/aws-sdk-go-v2/service/kms` with helpers for:
- Data Encryption Key (DEK) generation
- DEK encryption/decryption (envelope encryption)
- Key rotation awareness

Used by `platform/security/secrets` when `SECRETS_PROVIDER=aws-kms`.
