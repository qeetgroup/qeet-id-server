# Audit Logging

## Overview

Every mutation in Qeet ID produces an audit event. The audit log is:
- **Append-only** — events are never deleted or modified (soft-deletes in other tables do not affect audit records)
- **Hash-chained** — SHA-256 per-tenant chain detects tampering (see [ADR-0008](../adr/0008-hash-chained-audit-log.md))
- **Transactional** — written in the same `pgx.Tx` as the business operation
- **Queryable** — via the analytics domain API and admin console

Implementation: `domains/operations/audit`

## Audit event structure

```go
type Event struct {
    TenantID     string    // which tenant
    ActorType    string    // "user", "service", "agent", "system"
    ActorID      string    // user ID, API key ID, agent ID, etc.
    Action       string    // e.g., "user.created", "login.succeeded"
    ResourceType string    // e.g., "user", "api_key", "role"
    ResourceID   string    // ID of the affected resource
    Metadata     JSONB     // action-specific context
    IPAddress    string    // client IP (when applicable)
    UserAgent    string    // client user agent (when applicable)
    CreatedAt    time.Time
    PrevHash     string    // SHA-256 of previous event in chain
    Hash         string    // SHA-256 of this event
}
```

## Audited actions

All of the following generate audit events:

| Category | Actions |
|---|---|
| **Authentication** | login.succeeded, login.failed, login.mfa_required, logout, password.changed, passkey.registered, passkey.used |
| **Account** | user.created, user.updated, user.suspended, user.deleted, email.verified |
| **Organization** | org.created, org.updated, member.invited, member.joined, member.removed |
| **Authorization** | role.assigned, role.revoked, permission.granted, permission.revoked |
| **Developer** | api_key.created, api_key.revoked, webhook.created, agent.created, hook.triggered |
| **Federation** | oidc_client.created, saml_connection.created, scim.user_provisioned |
| **Security** | threat.detected, ip_rule.added, lockout.triggered, session.revoked |
| **Billing** | subscription.created, subscription.cancelled, payment.succeeded |
| **Compliance** | gdpr.export_requested, gdpr.deletion_requested |

## Hash chain verification

The chain ensures that any retroactive modification to audit records is detectable. To verify:

```bash
# Via the API (admin only):
GET /v1/audit/verify

# Returns:
{ "valid": true, "events_checked": 12483 }
# Or on tampering:
{ "valid": false, "broken_at_event_id": "01J...", "details": "hash mismatch" }
```

Programmatically, `audit.Verifier.Verify(ctx, tenantID)` walks the chain and recomputes each hash.

Verification is O(N) — for large tenants, schedule it asynchronously (not inline with requests).

## Querying audit events

Via the admin console: Access → Audit Log (filterable by action, actor, resource, date range).

Via the API:
```
GET /v1/audit?action=login.failed&limit=50
GET /v1/audit?actor_id=01J...&from=2026-01-01T00:00:00Z
GET /v1/audit?resource_type=role&resource_id=01J...
```

## SIEM streaming

Audit events can be forwarded in real-time to external security information and event management (SIEM) systems. Configured in the admin console (Operations → Log Sinks) or via `POST /v1/log-sinks`.

Supported destinations:
| Destination | Protocol |
|---|---|
| Splunk | HEC (HTTP Event Collector) |
| Datadog | Datadog Logs API |
| Generic | HTTP POST with HMAC-signed payload |

Delivery is **at-least-once** via the transactional outbox (see [ADR-0009](../adr/0009-transactional-outbox.md)). Events are forwarded within seconds of the triggering action.

Log sink configuration stored in `audit.log_sinks` (`migrations/0058`).

## Retention

Audit log retention is configurable per tenant (`operations/retention`). The default is to retain all events indefinitely. Tenants can configure auto-purge for events older than N days to manage storage costs, subject to any compliance requirements they must meet.

The hash chain remains valid after purging — the chain head for the earliest remaining event is preserved as a checkpoint.

## Access control

Audit log access is restricted to:
- **Admin console:** Users with `audit:read` permission (typically admins and owners)
- **API:** Bearer JWT with `audit:read` scope, or API key with `audit:read` in its scope list
- **SIEM streaming:** Configured sink receives events automatically; no direct DB access

Audit events are immutable — there is no `audit:write` scope. The only way to create audit events is through the normal application flow.
