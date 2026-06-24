# ADR-0008: SHA-256 Hash-Chained Audit Log

**Status:** Accepted  
**Date:** 2025-Q1 (implemented in migration 0023)  
**Deciders:** Qeet ID core team

---

## Context

Qeet ID serves enterprise customers who require a tamper-evident audit trail for compliance (SOC 2, GDPR, security investigations). Options:

1. **Simple append-only table** — easy to query; an attacker with DB write access can delete or modify rows without detection
2. **External immutable log (e.g., AWS CloudTrail, Datadog)** — true immutability but requires external dependency for a core security feature
3. **Hash-chained log** — each row includes a hash that chains to the previous row; tampering breaks the chain

## Decision

Implement a **per-tenant SHA-256 hash chain** in the `audit.audit_events` table.

**Schema addition (migration 0023):**
```sql
ALTER TABLE audit.audit_events
    ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN hash      TEXT NOT NULL DEFAULT '';
```

**Chain mechanics (`domains/operations/audit/audit.go`):**
- Each tenant has an independent chain (chain head = last `hash` for that `tenant_id`)
- First event: `prev_hash = '0000...0000'` (64 zero hex chars)
- Each subsequent event: `prev_hash = last_event.hash`
- `hash = SHA256(deterministic_json(prev_hash, tenant_id, actor_type, actor_id, action, resource_type, resource_id, created_at))`
- `audit.Record()` runs inside the caller's `pgx.Tx` — atomicity is guaranteed

**Verification:** `audit.Verifier.Verify(ctx, tenantID)` walks the entire chain, recomputing each hash and confirming it matches the stored value.

## Consequences

**Positive:**
- Tampering (delete, modify, insert) breaks the chain and is detected by any verification run
- Per-tenant isolation: a broken chain in one tenant doesn't affect others
- Self-contained: no external dependency needed for tamper evidence
- Audit records are append-only in practice (no UPDATE or DELETE on `audit_events`)

**Negative / watch-outs:**
- Chain walk is O(N) where N is the number of audit events for a tenant — verification of large tenants is slow; schedule verifications asynchronously, not inline with requests
- Concurrent writes to the same tenant's audit log could create a chain fork. Mitigation: `SELECT prev_hash FOR UPDATE` row lock on the chain head within the transaction
- SHA-256 is not post-quantum secure for long-term non-repudiation. For pre-1.0, this is acceptable; a migration to SHA-3 or a signature-based scheme can be done with a new migration
- The chain proves that the log hasn't been modified _since it was written_ — it does not prove that the original events were logged faithfully (that would require a separate signing mechanism)
