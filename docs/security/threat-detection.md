# Threat Detection

## Overview

Qeet ID records and responds to security anomalies through the `domains/access/threat-detection` context. Detection signals are recorded during authentication flows and contribute to automated responses (lockout, notification, SIEM alert).

## Signal types

### Brute-force / credential stuffing

**Trigger:** Repeated failed login attempts for the same user or from the same IP.

**Mechanism:**
- `domains/access/threat-detection/threat` — records `threat.Event` on each failed login
- `migrations/0052_security_events` — `auth.security_events` table
- `migrations/0041_login_lockout` — `auth.login_lockout` table for lockout state

**Response:**
- After N failures for the same account (configurable per tenant): account enters temporary lockout (`locked` error on subsequent attempts)
- Lockout duration is exponential-backoff: starts at 5 minutes, doubles per repeated lockout up to 24 hours
- Recovery: lockout expires automatically, or admin can manually unlock via `POST /v1/users/:id/unlock`

### Bot detection

**Trigger:** Request characteristics indicating automated behavior.

**Mechanism:** `domains/access/threat-detection/bot`

Bot scoring signals include:
- Request rate patterns (beyond rate limiting — unusual timing characteristics)
- User-agent entropy
- IP reputation (known hosting/VPN ranges)
- Missing browser-only headers

High-confidence bot signals can trigger:
- CAPTCHA challenge (returned as `bot_suspected: true` in login response)
- Temporary IP block via `POST /v1/ip-rules`

### Anomalous login signals

Recorded by `auth.Service.Login()` via the injected `AnomalyRecorder` interface:

- **New country/city** — first login from a location not seen before for this user
- **New device** — first login from a device fingerprint not seen before
- **Impossible travel** — login from a location incompatible with the previous login's location + time

These signals generate in-app notifications (`domains/operations/notifications`) for the affected user and SIEM events if a log sink is configured.

## IP allow/deny lists

Tenants can configure IP rules (`domains/access/risk/ipallow`):

```
POST /v1/ip-rules
{ "cidr": "192.168.1.0/24", "action": "allow" }  // allowlist
{ "cidr": "10.0.0.0/8",     "action": "deny"  }  // denylist
```

Rules are evaluated per-tenant on every request. Deny rules block the request with `403 Forbidden`. Allow rules can be used to whitelist specific corporate IP ranges.

IP rules are stored in `auth.ip_rules` (`migrations/0035_ip_rules`).

## Trusted devices

After a successful MFA verification, users can mark a device as trusted (`migrations/0054_trusted_devices`). Trusted devices skip MFA on subsequent logins (subject to a configurable trust duration).

Trusted device records store a device fingerprint (browser + OS identifiers, hashed). A device can be untrusted from the admin console or via `DELETE /v1/trusted-devices/:id`.

## Security notifications

The `domains/operations/notifications` context delivers in-app notifications to the affected principal:

- Login from new location
- New passkey registered
- Admin role assigned
- Anomaly detected
- Password changed

Notifications are accessible via `GET /v1/notifications` and surfaced in the admin console notification bell. They are persisted in `platform.notifications` (`migrations/0055`).

## SIEM event forwarding

All security events are forwarded to configured SIEM sinks (see [audit-logging.md](audit-logging.md) for sink configuration). The `domains/operations/siem` context handles fan-out to multiple destinations.

Security event payload example:
```json
{
  "type":      "threat.brute_force",
  "severity":  "high",
  "tenant_id": "01J...",
  "actor_id":  "01J...",
  "ip":        "203.0.113.42",
  "details":   { "failed_attempts": 12, "window_seconds": 60 },
  "timestamp": "2026-06-24T10:30:00Z"
}
```

## Observability

Threat detection activity is visible in:
- **Admin console:** Access → Security Events (filterable by type, severity, date)
- **Audit log:** Every threat detection event is also an audit log entry
- **SIEM stream:** Real-time forwarding if a log sink is configured
- **Prometheus:** `security_events_total{type="brute_force"}` counter (future — not yet wired)
