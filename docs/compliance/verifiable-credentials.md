# Verifiable Credentials

## Overview

Qeet ID supports W3C Verifiable Credentials (VCs) via JWT-VC format, implemented in `domains/developer/credentials/vc` (`migrations/0062_credentials`). VCs allow Qeet ID to act as a credential issuer — producing cryptographically signed attestations about users that can be verified by third parties without calling back to Qeet ID.

**Standards:** W3C Verifiable Credentials Data Model 1.1, JWT-VC profile

## Use cases

| Scenario | VC claim |
|---|---|
| Prove employment at an organization | `{ type: "EmployeeCredential", org: "Acme Inc", role: "Engineer" }` |
| Prove MFA enrollment status | `{ type: "MFACredential", methods: ["passkey", "totp"] }` |
| Prove identity verification level | `{ type: "IdentityAssurance", level: "ial2" }` |
| Prove access scope for an AI agent | `{ type: "AgentScopeCredential", allowed_scopes: [...] }` |
| Age/presence attestation | `{ type: "AgeAttestation", over_18: true }` |

## Issuing a credential

Credentials are issued via the developer API (requires `credentials:issue` scope or admin):

```
POST /v1/credentials/issue
Authorization: Bearer <admin or developer token>
Content-Type: application/json

{
  "subject_id":   "01J...",
  "type":         "EmployeeCredential",
  "claims":       { "org": "Acme Inc", "role": "Engineer", "since": "2025-01-01" },
  "expires_in":   86400,
  "revocable":    true
}
```

Response:
```json
{
  "credential_id": "01J...",
  "vc_jwt":        "<signed JWT-VC>",
  "expires_at":    "2026-06-25T10:00:00Z"
}
```

The `vc_jwt` is a standard JWT signed with Qeet ID's ES256 signing key. The subject receives this JWT and can present it to verifiers.

## Verifying a credential

Anyone can verify a credential (no authentication required):

```
POST /v1/credentials/verify
Content-Type: application/json

{
  "vc_jwt": "<the VC JWT>"
}
```

Response on valid credential:
```json
{
  "valid":        true,
  "credential_id": "01J...",
  "subject_id":   "01J...",
  "type":         "EmployeeCredential",
  "claims":       { "org": "Acme Inc", "role": "Engineer" },
  "issued_at":    "2026-06-24T10:00:00Z",
  "expires_at":   "2026-06-25T10:00:00Z",
  "revoked":      false
}
```

Response on invalid/revoked credential:
```json
{
  "valid":  false,
  "reason": "credential_revoked"
}
```

The verifier does not need to trust Qeet ID at verification time — the JWT signature is verified against Qeet ID's public key from `/jwks.json`.

## Revoking a credential

```
DELETE /v1/credentials/:id
Authorization: Bearer <admin token>
```

Revocation is recorded in `credentials.vc_revocations`. Subsequent verifications of the revoked credential return `{ "valid": false, "reason": "credential_revoked" }`.

**Note:** Revocation requires the verifier to call `/v1/credentials/verify` — there is no OCSP-style push revocation. If a verifier caches VC validity, they may not detect revocation until their cache expires.

## Storage

| Table | Content |
|---|---|
| `platform.vc_credentials` | Issued credential records (id, subject, type, claims, expiry, issued_by) |
| `platform.vc_revocations` | Revocation registry (credential_id, revoked_at, reason) |

Credentials are stored but the VC JWT itself is not re-issued from storage — it is generated at issuance time and must be retained by the subject. The API can re-issue if the original is lost (creates a new credential with new `vc_jwt`).

## JWT-VC format

```json
{
  "iss": "https://id.qeet.in",
  "sub": "01J...",
  "jti": "01J...",
  "iat": 1750000000,
  "exp": 1750086400,
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "EmployeeCredential"],
    "credentialSubject": {
      "id": "did:example:01J...",
      "org": "Acme Inc",
      "role": "Engineer"
    }
  }
}
```

Signed with ES256 using Qeet ID's primary signing key. The `kid` header allows verifiers to fetch the correct public key from `/jwks.json`.
