# ADR-0009: Transactional Outbox for Webhooks and Events

**Status:** Accepted  
**Date:** 2025-Q1 (implemented in migration 0002; DLQ in migration 0025)  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID needs to reliably deliver events to external systems:
- **Webhooks** — tenant-configured HTTP endpoints that receive identity events (user.created, login.succeeded, etc.)
- **SIEM streaming** — audit log forwarding to Splunk HEC, Datadog, generic HTTP sinks
- **Notifications** — in-app alerts for security events

A naive approach: after committing the business row, immediately POST to the webhook URL. This fails:
- If the POST fails (network error, webhook timeout), the event is lost
- If the service crashes between DB commit and POST, the event is lost
- If the webhook URL is slow, the login response is blocked

## Decision

Use the **transactional outbox pattern**:

1. Within the same `pgx.Tx` as the business row, write an event to `platform.outbox`
2. The transaction commits atomically — the business row and the outbox row are either both committed or neither
3. A background dispatcher (`platform/events/outbox.Dispatcher`) reads undelivered outbox rows and delivers them
4. On delivery failure, events enter `platform.outbox_dlq` (Dead Letter Queue) after N retries
5. The DLQ can be retried manually or automatically with backoff

**Key property:** The outbox row is written by the same transaction that performs the business mutation. An event can only be in the outbox if the corresponding business action succeeded.

Implementation:
- `platform/events/outbox` — dispatcher + DLQ
- `platform/workers.Supervisor` — manages the dispatcher goroutine lifecycle
- `migrations/0002_platform_outbox.up.sql`, `migrations/0025_outbox_dlq.up.sql`

## Consequences

**Positive:**
- **At-least-once delivery** guaranteed: events are never lost due to process crashes, network errors, or webhook timeouts
- Business mutations and event dispatch are decoupled: a slow webhook never blocks a login response
- DLQ provides visibility into failed deliveries; operators can retry or inspect failed events
- Foundation for future event-driven extraction: when a context is split into its own service, the outbox topic is already the integration point

**Negative / watch-outs:**
- **At-least-once** means webhooks may be delivered more than once. Webhook consumers should be idempotent. The webhook payload includes an event ID that consumers can use for deduplication
- Outbox table grows without pruning; a cleanup background worker should periodically remove delivered events older than N days
- The dispatcher adds a slight latency between the mutation and webhook delivery (typically < 1 second with a polling interval)

**Note on SIEM:** SIEM streaming uses the same outbox infrastructure. Log sinks are configured in `audit.log_sinks` (`migrations/0058_log_sinks`); the dispatcher fans out audit events to all configured sinks.
