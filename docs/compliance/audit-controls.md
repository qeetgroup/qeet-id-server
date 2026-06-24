# Audit Controls

## Purpose

The audit log provides a tamper-evident, append-only record of all significant actions in Qeet ID. It supports:
- **Security investigations** — trace the sequence of events leading to an incident
- **Compliance audits** — demonstrate that access controls were enforced
- **Forensics** — verify that no unauthorized changes were made to audit records
- **SIEM integration** — forward events to external security platforms in real time

## Tamper evidence

The audit log uses a SHA-256 hash chain (per tenant) to detect tampering. See [ADR-0008](../adr/0008-hash-chained-audit-log.md) and [../security/audit-logging.md](../security/audit-logging.md) for implementation details.

**What tampering looks like and how it's detected:**

| Tampering action | Detection |
|---|---|
| Delete an audit row | Next row's `prev_hash` won't match the gap |
| Modify an audit row's fields | Row's stored `hash` won't match recomputed hash |
| Insert a row mid-chain | Subsequent rows' `prev_hash` values will be inconsistent |
| Reorder rows | Chain walk order will produce mismatches |

**Verification:** `GET /v1/audit/verify` (admin only) returns `{ "valid": true }` or identifies the first broken link.

## Access controls

| Role | Access |
|---|---|
| Organization owner | Full audit log for their tenant |
| Admin | Full audit log for their tenant |
| Member | Own activity only (login history, own changes) |
| API key | `audit:read` scope required |
| SIEM sinks | Automatic forwarding (no direct DB access) |

Audit records are never writable via the API. `audit:write` scope does not exist.

## Compliance-relevant event categories

### Access events
- `login.succeeded`, `login.failed`, `login.mfa_required`
- `session.created`, `session.revoked`
- `passkey.registered`, `passkey.used`
- `api_key.created`, `api_key.revoked`

### Identity management
- `user.created`, `user.updated`, `user.suspended`, `user.deleted`
- `org.created`, `org.updated`
- `member.invited`, `member.joined`, `member.removed`

### Authorization changes
- `role.assigned`, `role.revoked`
- `permission.granted`, `permission.revoked`
- `rebac.tuple_added`, `rebac.tuple_removed`

### Security events
- `threat.detected` (with type: brute_force, credential_stuffing, etc.)
- `lockout.triggered`, `lockout.cleared`
- `ip_rule.added`, `ip_rule.removed`

### Configuration changes
- `oidc_client.created`, `oidc_client.updated`
- `saml_connection.created`, `saml_connection.updated`
- `webhook.created`, `webhook.updated`
- `auth_hook.created`, `auth_hook.updated`
- `retention_policy.updated`

### Compliance events
- `gdpr.export_requested`, `gdpr.deletion_requested`
- `gdpr.user_purged`

## Export and reporting

**API export:**
```
GET /v1/audit?from=2026-01-01T00:00:00Z&to=2026-06-30T23:59:59Z&format=json
```

**Admin console:** Operations → Audit Log → Export (CSV or JSON).

For continuous export (compliance archival), configure a SIEM log sink to forward events to an external storage system in real time.

## Retention and archival

Default: audit events are retained indefinitely.

To configure retention:
```
PUT /v1/retention
{ "audit_retention_days": 2555 }  // 7 years
```

Note: Regulatory requirements vary. Consult your compliance officer before configuring auto-purge. Common requirements:
- SOC 2: 1 year minimum
- PCI-DSS: 1 year minimum
- HIPAA: 6 years minimum
- GDPR: No mandated retention period (data minimization principle applies)
