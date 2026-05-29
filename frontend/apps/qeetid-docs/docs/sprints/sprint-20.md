# Sprint 20 — Platform & Infra (#33–#37) + 🚀 Data Residency + BYOK (D14)

| | |
|---|---|
| **Window** | 2027-04-12 → 2027-04-30 (3 weeks) |
| **Theme** | Production-scale platform: billing, streaming, storage, observability, compliance posture — and data sovereignty |
| **Depends on** | All prior sprints (this hardens + monetizes the whole platform) |
| **Closes** | Gaps **#33** (billing), **#34** (Kafka), **#35** (S3), **#36** (SOC2/ISO posture), **#37** (observability); New differentiator **D14** |
| **Status** | ⬜ Not started |

**Why:** Everything works and is differentiated; now make it **scale, earn, and pass an audit** — and offer what regulated/EU customers can't get cleanly elsewhere: **per-tenant data residency + bring-your-own encryption keys**.

---

## Part A — 🧪 Test the newly-built feature (E2E)

### 🧪 SCENARIO 20.1 — Billing (#33)
- **Steps:** subscribe a tenant to a plan (Stripe test mode); exceed a plan limit (e.g. MAU); downgrade/cancel.
- **Pass:** [ ] plan enforced (limits gate features) [ ] usage metered (MAU/MAO/connections) [ ] webhooks from Stripe reconcile state [ ] proration/cancel handled [ ] `tenant.plan` actually does something now.

### 🧪 SCENARIO 20.2 — Event streaming (#34) + asset storage (#35)
- **Pass:** [ ] outbox events publish to Kafka/queue (swap `LogPublisher`) with ordering + at-least-once [ ] branding/theme assets upload to S3 (presigned), served via CDN, virus/size-checked.

### 🧪 SCENARIO 20.3 — Observability (#37)
- **Pass:** [ ] OpenTelemetry traces span request→DB→outbox [ ] RED metrics (rate/errors/duration) per endpoint [ ] audit→SIEM stream [ ] dashboards + alerts wired.

### 🧪 SCENARIO 20.4 — Compliance posture (#36)
- **Pass:** [ ] live SOC2/ISO posture dashboards (built on D10 evidence autopilot) show real control status [ ] data-retention automation runs.

### 🧪 SCENARIO 20.5 — Data Residency + BYOK (D14)
- **Steps:** create a tenant pinned to region `eu`; supply a customer KMS key (BYOK); write PII; attempt cross-region read.
- **Expect:** PII stored only in the pinned region; field-level encryption uses the customer's KMS key; revoking the customer key renders that tenant's PII unreadable (crypto-shred); residency enforced.
- **Pass:** [ ] region pinning enforced (no PII leaves region) [ ] field-level encryption with customer KMS [ ] key revocation → crypto-shred [ ] residency reflected in audit/exports.

**Part A exit:** scenarios green; full-platform regression (`make test-api`, `make test-backend`) green.

---

## Part B — Build

### Platform/infra (#33–#37)
- **Billing** `internal/billing/`: Stripe integration, plan/entitlement enforcement middleware, metering (MAU/MAO/connections/SSO), customer portal, dunning. Migration `0045_billing.up.sql`. Admin billing screen → real.
- **Streaming** (#34): outbox `KafkaPublisher` (or NATS/SQS) behind the existing publisher interface; ordering + idempotency keys.
- **Storage** (#35): S3 (or compatible) for branding/theme/export assets; presigned upload/download; scanning + limits.
- **Observability** (#37): OpenTelemetry traces + metrics + logs; per-tenant SLOs (ties to Sprint-18 canaries); audit→SIEM exporter.
- **Compliance posture** (#36): finish D10's evidence autopilot into live SOC2/ISO dashboards + scheduled evidence packs + retention automation (replaces remaining compliance stubs).

### D14 — Data Residency + BYOK
- **Backend** `internal/residency/` + `internal/crypto/kms/`: per-tenant **region pinning** (route reads/writes to the tenant's region; block cross-region PII), **field-level encryption** of PII with a per-tenant DEK wrapped by a customer-supplied KMS key (AWS KMS / GCP KMS / Vault / HSM via an interface); **crypto-shred** on key revocation; residency tags in audit + exports. Migration `0046_residency_byok.up.sql`.
- **Frontend (admin)**: tenant **Residency & Encryption** settings (region, KMS key ARN/URI, key-rotation, "crypto-shred this tenant").

**Docs**: `content/docs/platform/billing.mdx`, `content/docs/platform/observability.mdx`, `content/docs/compliance/posture.mdx`, `content/docs/security/data-residency-byok.mdx`.

### Acceptance criteria
- [ ] Plans/entitlements enforced + metered; Stripe state reconciles via webhooks.
- [ ] Events stream to Kafka/queue with ordering + at-least-once; assets in S3 + CDN.
- [ ] OTel traces/metrics + SIEM export live; per-tenant SLOs visible.
- [ ] Live SOC2/ISO posture + scheduled evidence + retention automation (no compliance stubs left).
- [ ] Per-tenant region pinning + customer-KMS field encryption + crypto-shred all verified.

---

## Definition of Done
- [ ] Part A: all scenarios pass + **full-platform regression green**.
- [ ] Part B: `billing`, Kafka publisher, S3 storage, OTel, compliance posture, `residency`+`kms` modules, migrations, tests green.
- [ ] Admin billing + residency/encryption + compliance dashboards real (all stubs replaced).
- [ ] `platform/*`, `compliance/posture.mdx`, `security/data-residency-byok.mdx` published.
- [ ] Roadmap: #33–#37 checked; D14 noted; status ✅; changelog filled.
- [ ] **Program close-out:** update [Competitive Analysis & Roadmap](../COMPETITIVE-ANALYSIS-AND-ROADMAP.md) — flip the full gap matrix; Qeet ID now covers every analysed category. Re-baseline for the next horizon.

## Changelog
| Date | Change |
|---|---|
| 2026-05-29 | Sprint defined. |
