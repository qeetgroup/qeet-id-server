# platform/security/signing

Request/payload signing utilities beyond JWT (e.g., webhook HMAC signatures, SAML XML-Dsig).

Current signing implementations:
- Webhook HMAC-SHA256 signing: `domains/developer/webhooks/webhook.go`
- JWT signing: `platform/security/jwt/`
- SAML assertion signing: `domains/federation/saml/`

Planned: unified `Signer`/`Verifier` interface over all signing schemes.
