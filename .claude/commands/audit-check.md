---
description: Check that every backend mutation calls audit.Record and outbox.Enqueue where appropriate.
---

Audit the backend for missing audit/outbox calls.

The convention (per [CLAUDE.md](../../CLAUDE.md) — Database conventions):
- Every mutation goes through a transaction.
- Inside that transaction it should call `audit.Record(ctx, tx, ...)` from [backend/internal/audit/audit.go](../../backend/internal/audit/audit.go).
- Domain events that other services care about should `outbox.Enqueue(ctx, tx, Event{...})` from [backend/internal/platform/outbox/outbox.go](../../backend/internal/platform/outbox/outbox.go).

Steps:

1. Find every `service.go` (or collapsed module file) under `backend/internal/`.
2. For each file, identify mutating functions — heuristics: name starts with `Create`, `Update`, `Delete`, `Revoke`, `Rotate`, `Enable`, `Disable`, `Set`, `Issue`; or function body contains `INSERT`, `UPDATE`, `DELETE` SQL.
3. For each such function, check whether the body (or a helper it calls) invokes `audit.Record`. Flag any that don't.
4. Separately, flag mutations that look user-visible (anything in `user`, `auth`, `rbac`, `tenant`, `apikey`, `mfa`, `passkey`, `social`, `webhook`) but don't call `outbox.Enqueue`.
5. Filter by `$ARGUMENTS` if non-empty (e.g. `user` only audits `internal/user/`).

Output: markdown table — `Module | Function | Missing` (audit / outbox / both). End with a short summary of how many findings and which look most consequential.

Read-only command. Do not fix anything automatically — the user reviews first.
