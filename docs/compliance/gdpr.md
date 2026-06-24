# GDPR Compliance

Qeet ID implements GDPR rights through the `domains/operations/compliance` context. This document covers the technical implementation of each GDPR obligation.

## Data Qeet ID holds about a user

| Data category | Location | Retention |
|---|---|---|
| Email address | `user.users.email` | Until deletion |
| Display name | `user.users.display_name` | Until deletion |
| Password hash | `auth.credentials.hash` | Until deletion |
| Passkey public keys | `auth.passkey_credentials` | Until deletion |
| MFA secrets | `auth.mfa_secrets` | Until deletion |
| Login history | `audit.audit_events` (action=login.*) | Configurable; default indefinite |
| IP addresses | `audit.audit_events.ip_address` | With audit log |
| Session records | `auth.sessions` | Until expiry or deletion |
| Notification inbox | `platform.notifications` | Configurable |
| Billing records | `platform.billing_*` | Statutory minimum (7 years typical) |

Qeet ID does **not** store:
- Plaintext passwords
- Passkey private keys (stored on device, never leave it)
- Payment card numbers (handled by Stripe/Razorpay)

## Right of Access (Subject Access Request)

A user can request all data Qeet ID holds about them:

**Self-service (user-initiated):**
```
GET /v1/compliance/export
Authorization: Bearer <user token>
```

**Admin-initiated (on behalf of user):**
```
POST /v1/compliance/export
Authorization: Bearer <admin token>
{ "user_id": "01J..." }
```

Response: JSON document containing all personal data fields, audit history, and associated records. Download as `.json` file from the admin console (Compliance → Data Export).

The export is generated asynchronously for large datasets. A notification is sent to the user's email when ready.

## Right to Erasure (Right to be Forgotten)

Deletion is a two-phase process:

**Phase 1: Soft delete (immediate)**
```
DELETE /v1/compliance/users/:id
Authorization: Bearer <admin token>
```
- Sets `user.users.deleted_at = NOW()`
- Invalidates all sessions and refresh tokens
- Removes the user from all organization memberships
- User cannot log in; data is not yet purged

**Phase 2: Purge (scheduled)**
The `operations/retention` background worker runs periodically and permanently deletes soft-deleted user records after the configured retention period (default: 30 days). The retention period gives time to handle any legal holds or billing disputes before permanent deletion.

Permanent deletion removes:
- `user.users` row
- `auth.credentials` rows
- `auth.passkey_credentials` rows
- `auth.mfa_secrets` rows
- `auth.sessions` rows
- `platform.notifications` rows
- Personal data fields in `audit.audit_events` (pseudonymized, not deleted — required for integrity)

**Audit log handling:** GDPR audit events (the deletion request itself) are retained in the audit chain. Personal data fields in pre-existing audit events are pseudonymized (user email replaced with `[deleted]`, IP addresses zeroed) rather than deleted, to preserve audit chain integrity.

## Right to Rectification

Users can update their own data via:
- Email change: `PUT /v1/users/me/email` (requires re-verification)
- Display name: `PUT /v1/users/me`
- Profile fields: `PUT /v1/users/me/profile`

Admins can update user data via `PUT /v1/users/:id`.

## Data Portability

The SAR export (described above) is in JSON format, designed to be human-readable and machine-parseable. The export includes enough structure to be imported into another identity system.

## Consent

The hosted login app (`apps/login/src/app/consent/`) handles OAuth 2.0 consent flows. When an OIDC client requests scopes, users are shown a consent screen listing the requested permissions. Consent decisions are recorded in `auth.oidc_grants`.

## Data Retention

Tenant admins configure data retention policies via:
```
PUT /v1/retention
{ "deleted_user_purge_days": 30, "audit_retention_days": 365 }
```

The `operations/retention` background worker enforces these policies.

## Privacy by design

- **Pseudonymization:** User IDs are ULIDs (not sequential integers); they are not guessable
- **Minimal collection:** Only data required for identity management is collected
- **Access control:** Audit log access is RBAC-gated; personal data not exposed to non-admin roles
- **Encryption at rest:** Secrets vault uses AES-256-GCM; database encryption is handled at the PostgreSQL/cloud level

## GDPR-relevant audit events

All GDPR-related actions generate audit events with action prefix `gdpr.*`:
- `gdpr.export_requested`
- `gdpr.export_completed`
- `gdpr.deletion_requested`
- `gdpr.user_purged`
- `gdpr.consent_given`
- `gdpr.consent_revoked`
