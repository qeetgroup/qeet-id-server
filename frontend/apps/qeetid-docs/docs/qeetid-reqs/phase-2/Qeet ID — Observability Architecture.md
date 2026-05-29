# Qeet ID — Observability Architecture

### 1. Document Information

|  |  |
| --- | --- |
| **Document Name** | Observability Architecture |
| **Project Name** | Qeet ID |
| **Parent Company** | Qeet Group |
| **Subsidiary** | Qeet ID (Standalone) |
| **Document Version** | v1.0 |
| **Prepared By** | SRE Lead |
| **Date** | May 19, 2026 |
| **Status** | Draft — Pending Stakeholder Sign-off |

---

### 2. Purpose & Scope

This document defines Qeet ID's observability architecture — the three pillars of logging, metrics, and tracing; the chosen tooling; the SLO architecture; the alerting topology; the dashboards; synthetic and real-user monitoring; the dedicated audit log pipeline; retention; sampling; correlation; on-call tooling and runbook linkage; and the customer-facing observability surface.

In an Authentication & Authorization platform that promises 99.9% uptime and operates on the critical path of every customer's user login, observability is the difference between catching an outage in a status-page tweet and catching it before it propagates. Logging, metrics, and tracing are not optional; services without them fail their integration test gate.

The audience is the SRE Lead, every team lead with on-call responsibility, the DevOps Lead, the Security Architect, the Compliance Officer (for audit pipeline), and the Solution Architect.

This document depends on [Microservices Decomposition](Qeet ID%20%E2%80%94%20Microservices%20Decomposition%20%26%20Service%20Boundaries.md), [Infrastructure & Deployment Architecture](Qeet ID%20%E2%80%94%20Infrastructure%20%26%20Deployment%20Architecture.md), and [Security Architecture](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md).

---

### 3. The Three Pillars

The chosen stack:

| Pillar | Tool | Purpose |
| --- | --- | --- |
| Logs | Loki + Grafana (or ELK — open decision OQ-OBS-01) | Structured JSON logs; centralised query |
| Metrics | Prometheus + Grafana | Time-series; SLOs; alerting |
| Traces | OpenTelemetry SDK + Jaeger or Tempo (open OQ-OBS-02) | Distributed traces; latency drilldown |
| Alerts | Alertmanager → PagerDuty + Slack | On-call paging |
| Synthetic | Self-hosted multi-region probes + Cloudflare Workers / Checkly (open OQ-OBS-03) | External user-perspective monitoring |
| RUM (admin dash + dev portal) | Grafana Faro or Datadog RUM (open OQ-OBS-04) | Real-user front-end metrics |
| Status page | Statuspage.io or self-hosted (open OQ-OBS-05) | Customer-facing status |
| Trace propagation | W3C Trace Context | Cross-service correlation |

The open decisions (OQ-OBS-01..05) are tractable; preliminary direction in §17.

### 3.1 Why OSS-Primary

The OSS stack (Prometheus + Loki + Tempo + Grafana, the "PLTG" stack) is cloud-portable, cost-predictable at our scale, and avoids the per-host-or-per-metric pricing that erodes margin on a high-cardinality, multi-tenant platform. We allow Datadog as a *backup* observability surface for cases where its dashboards or APM features add marginal value — but the SLOs and alerts of record live in the OSS stack so we are not pricing-locked.

---

### 4. Logging Stack

### 4.1 Format

All logs are **structured JSON**. One JSON object per line. Schema (NFR LG-02):

```json
{
  "timestamp": "2026-05-19T12:34:56.789Z",
  "level": "INFO",
  "service": "auth",
  "version": "v1.42.3",
  "environment": "prod-use1",
  "request_id": "req_01HX...",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "span_id": "b7ad6b7169203331",
  "tenant_id": "org_acme",
  "user_id": "user_8f3...",
  "event": "auth.login.succeeded",
  "method": "passkey",
  "duration_ms": 142,
  "result": "success",
  "client_ip_country": "US",
  "client_ip": "redacted",
  "extra": { ... event-specific structured fields ... }
}
```

### 4.2 Standard Fields

- `timestamp` ISO 8601 UTC with millisecond precision.
- `level` one of `DEBUG | INFO | WARN | ERROR | CRITICAL`. Production default INFO (NFR LG-05).
- `service` — service identifier (`auth`, `token`, etc.).
- `version` — semantic version of the service.
- `environment` — `dev | staging | prod-use1 | prod-euw1`.
- `request_id` — server-generated UUID; correlation ID across services.
- `trace_id` / `span_id` — W3C Trace Context.
- `tenant_id` — for tenant-scoped logs.
- `user_id` — when relevant; opaque ID, never email.

### 4.3 No PII Rule (NFR LG-04)

Logs **never** contain emails, phone numbers, plaintext passwords, JWT tokens, or other PII. User identifiers are opaque IDs. Where a customer-supplied email shows up in error messages (e.g., "user not found by email X"), the email is hashed or redacted before logging. CI lint catches obvious PII patterns.

### 4.4 Pipeline

```
   Service pod
     │ stdout
     ▼
   Promtail / Fluent Bit (DaemonSet, per node)
     │ Reads container stdout; enriches with k8s metadata
     ▼
   Otel Collector (regional)
     │ Routes by destination
     ▼
   ┌─────────────────────┬──────────────────┐
   ▼                     ▼                  ▼
   Loki (hot 30d)   S3 (cold 12m)    Splunk/Datadog (optional customer mirror)
```

### 4.5 Retention

| Class | Hot | Cold |
| --- | --- | --- |
| Application logs | 30 d Loki | 12 m S3 (NFR LG-07) |
| Audit logs | 12 m Postgres + Loki | 3 y S3 (NFR LG-08; Compliance AL-05) |
| Security event logs | 3 y hot (NFR LG-09) | — |

### 4.6 Ingestion Latency

NFR LG-06: < 60 s from event to searchable in centralised store. The Promtail-to-Loki pipeline routinely achieves < 10 s in practice.

### 4.7 Log Access Control

Loki access via Grafana with team-RBAC. Production logs containing tenant data are accessible to on-call rotation members; queries are themselves audited. Cross-tenant log search by ops requires explicit ticket (Security §11.4 cross-tenant procedure).

---

### 5. Metrics Stack

### 5.1 Collection

- Every service exposes Prometheus metrics on `/metrics` over HTTP/2 inside the mesh.
- Prometheus servers in each region scrape services and the mesh sidecars.
- Remote-write forwards aggregated metrics to a long-term store (Mimir or Thanos — open OQ-OBS-06).

### 5.2 Standard Metric Set

Every HTTP service emits at minimum:

| Metric | Type | Labels |
| --- | --- | --- |
| `qeetify_http_requests_total` | Counter | service, method, route, status, tenant_plan |
| `qeetify_http_request_duration_seconds` | Histogram | service, method, route, status |
| `qeetify_http_in_flight_requests` | Gauge | service |
| `qeetify_dependency_calls_total` | Counter | service, dependency, status |
| `qeetify_dependency_call_duration_seconds` | Histogram | service, dependency |
| `qeetify_queue_depth` | Gauge | service, queue |
| `qeetify_event_published_total` | Counter | service, topic |
| `qeetify_cache_operations_total` | Counter | service, cache, operation, result |

Per NFR MX-01..MX-08 metric categories.

### 5.3 Tenant-Scoped Cardinality

Tenant-scoped metrics use a `tenant_plan` label rather than `tenant_id` for general metrics to bound cardinality. Per-tenant detail is queried from the audit log or from a separate "per-tenant" metric set that exists for select indicators (active sessions, error rate) and is allowed to grow with the tenant count.

### 5.4 Granularity & Retention (NFR MX)

| Class | Scrape interval | Retention |
| --- | --- | --- |
| Request metrics | 10 s | 13 months |
| Business metrics (MAUs, MFA enrolment, passkey adoption) | 1 min | 5 years |
| Resource metrics | 30 s | 13 months |
| DB metrics | 30 s | 13 months |
| Security metrics | 1 min | 3 years |
| SLO metrics | continuous | 13 months |

### 5.5 Cardinality Discipline

A "cardinality budget" per service is monitored: metric label combinations beyond budget alert the owning team to refactor. Common offenders: per-user labels, per-URL-path labels with high-fan-out, free-text labels.

---

### 6. Distributed Tracing

### 6.1 Standards & Tooling

- **OpenTelemetry** SDK across every service. Auto-instrumentation where the framework supports it; manual where needed.
- **W3C Trace Context** propagation: `traceparent` and `tracestate` headers carry trace IDs across services and to Kafka events.
- **Jaeger** OR **Tempo** as the trace backend (open OQ-OBS-02). Grafana for UI.

### 6.2 Sampling

NFR TR-02: head-based sampling at 10% baseline; 100% of errors and 100% of slow requests.

Implementation:

- Otel SDK configured with `parentbased_traceidratio(0.1)`.
- Sampling decision propagates downstream (parent-based ensures consistency across services).
- Tail-based sampling layer in the collector promotes slow-but-otherwise-sampled-out traces to 100%.
- 100% sampling for traces involving any service that returned a 5xx.

### 6.3 Span Attributes (NFR TR-04)

Every span carries:

- `tenant.id` (hashed — short hash, not the raw UUID, to constrain cardinality in trace search backends)
- `tenant.plan` (free/growth/enterprise)
- `http.route`
- `http.status_code`
- `db.system` / `db.statement` (sanitised, parameters elided)
- `messaging.system` / `messaging.destination` for Kafka producers/consumers

### 6.4 Correlation

`trace_id` and `span_id` appear in every log line (NFR TR-06). Grafana's logs-to-traces and traces-to-logs links work end-to-end. Incident triage pivots between logs, metrics, and traces with a single click.

### 6.5 Retention

NFR TR-05: 7 days hot; 30 days cold.

---

### 7. SLO Architecture

### 7.1 SLO Inventory

Per NFR §11.5 the SLO catalogue:

| SLO | Target | Error budget (monthly) |
| --- | --- | --- |
| OAuth `/token` success rate | 99.95% | 21.9 min |
| OAuth `/token` p95 latency < 200 ms | 99.5% | 3.6 h |
| Login flow completion rate | 99.5% | 3.6 h |
| SAML assertion processing success | 99.9% | 43.8 min |
| SCIM provisioning success | 99.9% | 43.8 min |
| SCIM `active=false` propagation < 60 s | 99.9% | 43.8 min |
| Webhook delivery within retry policy | 99.95% | 21.9 min |
| Admin dashboard availability | 99.5% | 3.6 h |
| Audit log ingestion completeness | 100% | 0 |

### 7.2 SLI Computation

Each SLO has a documented **Service Level Indicator (SLI)** — a Prometheus query that computes the SLO over the rolling 28-day window. Example (token success):

```promql
sum(rate(qeetify_http_requests_total{service="token",route="/oauth/token",status!~"5.."}[28d]))
  /
sum(rate(qeetify_http_requests_total{service="token",route="/oauth/token"}[28d]))
```

### 7.3 Error Budget

Burn rate alerting at multiple windows (Google SRE multi-window strategy):

- 14-day burn at 2× normal → ticket.
- 6-hour burn at 5× normal → page.
- 1-hour burn at 14.4× normal → page (incident likely).

### 7.4 Error Budget Policy

When an SLO error budget is **exhausted**:

- Deploys to that service are **paused** (NFR SL — last line). Pause is auto-enforced via the CI pipeline checking burn rate gate.
- Engineering work is **redirected** from feature work to reliability for that service until the budget is restored.
- A post-mortem identifies the contributing changes.

---

### 8. Alerting Architecture

### 8.1 Alert Routing

```
   Alertmanager
     │
     ├─ severity = critical (P1) ──▶ PagerDuty (primary on-call) ──▶ SMS + phone
     │                                                              ──▶ Slack #incident
     │                                                              ──▶ CISO if security-flagged
     │
     ├─ severity = high (P2)     ──▶ PagerDuty (primary on-call)
     │
     ├─ severity = medium (P3)   ──▶ Slack #alerts-prod + Linear ticket
     │
     ├─ severity = low (P4)      ──▶ Slack #alerts-prod
     │
     └─ informational            ──▶ Slack #ops-firehose
```

### 8.2 Alert Categories (NFR AL-01..AL-05)

| Severity | Trigger examples | Response time |
| --- | --- | --- |
| P1 | Auth endpoint down; tenant isolation breach; security incident; KMS unavailable; signing key compromise; >5% error rate sustained 5 min | Ack < 5 min; mitigation < 30 min |
| P2 | p95 latency > target 5 min; single AZ degradation; >1% error rate; database failover triggered | Ack < 15 min |
| P3 | Queue lag > threshold; cert expiry < 30d; certificate-renewal failure; non-critical dependency degraded | Ack < 1 h |
| P4 | Capacity approaching budget; deprecated API usage detected; cost anomaly | Next business day |

### 8.3 Alert Quality

Every alert has:

- A clear, actionable title.
- A linked runbook (NFR IR-08).
- A clear "ack" path and clear ownership.
- A documented owning team.

Alerts without runbooks fail review.

A weekly "alert hygiene" review removes noisy alerts, refines thresholds, and elevates under-monitored areas. The metric `alerts_acknowledged_without_action` is published; high values trigger refactoring.

---

### 9. Dashboard Catalogue

A handful of canonical dashboards owned by the SRE team; teams maintain their own service-specific dashboards.

### 9.1 Platform-Wide Dashboards

| Dashboard | Owner | Audience |
| --- | --- | --- |
| Platform health | SRE | Everyone — first link on Grafana home |
| SLO status (every SLO + burn rates) | SRE | SRE + Engineering Leads |
| Auth funnel (login attempts → success rate) | Team Auth + Product | Eng + Product |
| Tenant top-talkers | SRE | SRE + Customer Success |
| Cost / unit economics ($/MAU) | DevOps + Finance | Finance + Leadership |
| Deploys today | Platform | SRE + Engineering |
| Open incidents | SRE | Everyone |

### 9.2 Service Dashboards

Each service owns a dashboard with:

- Request rate, error rate, latency (RED method)
- Saturation (CPU, memory, connection pool)
- Top errors (sampled stack traces)
- Dependency health (downstream call latency / error rate)
- Custom business metrics

### 9.3 Tenant-Level Dashboards (Customer-Facing)

Customer-facing dashboards in the admin dashboard show, per their own tenant:

- Live MAU
- Login success rate (rolling 24 h)
- MFA adoption rate
- Passkey adoption rate
- API call volume
- Security event summary

This is differentiator-relevant — competitors expose this poorly.

---

### 10. Synthetic Monitoring

### 10.1 Probes

Synthetic checks run from at least 4 external locations (different from Qeet ID-hosted regions):

- North America East (different from us-east-1)
- North America West
- EU (different from eu-west-1)
- APAC (Singapore region of probe vendor)

### 10.2 Probe Suite

| Probe | Frequency | Asserts |
| --- | --- | --- |
| `/.well-known/openid-configuration` reachable + valid JSON | 30 s | 200 + JSON schema |
| `/.well-known/jwks.json` reachable + valid keys | 30 s | 200 + has ≥ 2 keys |
| `/oauth/token` synthetic refresh against test-tenant | 1 min | 200 + valid token |
| Hosted login page reachable + key elements present | 1 min | 200 + DOM check |
| Magic link end-to-end (using a sink mailbox) | 5 min | E2E success |
| Passkey assertion synthetic (using a software authenticator) | 5 min | E2E success |
| SAML metadata endpoint | 5 min | 200 + valid XML |
| SCIM endpoint health | 5 min | 200 |
| Admin dashboard login | 5 min | E2E success |

Failures page the on-call within 2 min.

### 10.3 Tooling

Self-hosted synthetic checks via lightweight workers in each probe region OR a SaaS (Checkly) — OQ-OBS-03.

---

### 11. Real-User Monitoring (RUM)

The admin dashboard and developer portal collect anonymous, opt-in RUM:

- Page load time
- Time to interactive
- Largest Contentful Paint
- API call latency (from browser, end-to-end including network)
- JS error rate
- Browser / OS distribution (for compatibility planning)

RUM does **not** capture credentials, PII, or anything the user types beyond URL paths.

End-user login pages also collect minimal RUM (hosted login pages — page load and conversion only) per tenant configuration.

### 11.1 Conversion Telemetry

A subset of RUM tracks login funnel conversion:

- Login page loaded
- First credential entered
- MFA challenged
- MFA verified
- Token issued

The funnel surfaces drop-off points and informs UX work.

---

### 12. Audit Log Pipeline (Separate from Operational Logs)

The audit pipeline is its own thing. It is durable, tamper-evident, and never sampled. It is **not** the operational log pipeline.

### 12.1 Architecture

(Detail in [Database Design §13](Qeet ID%20%E2%80%94%20Database%20Design%20%26%20Data%20Model.md) and [Security Architecture §13](Qeet ID%20%E2%80%94%20Security%20Architecture%20%28Zero%20Trust%29.md).)

```
   Service emits audit event on Kafka audit.{plane}.{verb}
        │ partitioned by tenant_id
        ▼
   Audit Ingestion Service
        │
        ├──▶ PostgreSQL audit_log_hot (12-month, partitioned)
        │       - Hash-chained per tenant per day
        │
        ├──▶ S3 audit-cold (12–84-month, Object Lock, Glacier tier)
        │
        └──▶ OpenSearch index (90-day, per-tenant)
```

### 12.2 Differences from Operational Logging

| Feature | Operational logs | Audit logs |
| --- | --- | --- |
| Tool | Loki | Postgres + S3 + OpenSearch |
| Sampling | n/a (all logged); content may be redacted | None ever |
| Tamper evidence | none expected | Hash chain + Object Lock |
| Retention | 30 d hot / 12 m cold | 12 m hot / 36 m total (3y) |
| Customer-accessible | No | Yes (via dashboard / export API) |
| Loss tolerance | acceptable | none (NFR SL-08) |

### 12.3 Customer Audit Export

The audit log is exportable in JSON / CSV via dashboard or API. Integration adapters write to SIEM platforms (Splunk, Sentinel, Datadog, Sumo Logic — NFR IC-04).

---

### 13. Log / Metric / Trace Retention & Tiering Summary

| Source | Hot | Cold | Total |
| --- | --- | --- | --- |
| Application logs | 30 d Loki | 12 m S3 | 12 m |
| Audit logs | 12 m Postgres + Loki mirror | 24 m S3 Glacier | 36 m (3 y) |
| Security event logs | 3 y hot | — | 3 y |
| Metrics — request | 13 m | — | 13 m |
| Metrics — business | 5 y | — | 5 y |
| Metrics — security | 3 y | — | 3 y |
| Traces | 7 d | 30 d S3 | 30 d |

---

### 14. Trace Sampling Strategy

Recap of §6.2:

- Head-based at 10% baseline.
- Tail-based promotion to 100% for errors and slow requests (latency > p99 budget).
- Per-tenant tail-based 100% for tenants experiencing active production incidents.
- Per-flow 100% for high-sensitivity flows like SAML SLO and SCIM `active=false`.

Sampling rate is configurable per service via Helm values; SREs raise sampling in response to incidents to capture richer data.

---

### 15. Correlation Across Pillars

The `request_id` is the universal correlation key:

- Generated at API Gateway if absent.
- Echoed in all responses (`X-Request-ID`).
- Carried in every internal hop (header + service token claim).
- Present in every log line of that request.
- Equal to the trace ID's leading 16 bytes for traceability into the trace UI.
- Propagated to Kafka events spawned by the request (the consumer logs it).
- Recorded in the audit log.

A support ticket that references `request_id req_01HX...` lets engineering traverse logs → metrics → traces → audit log in one click.

---

### 16. On-Call Tooling & Runbook Linking

### 16.1 Tooling

- **PagerDuty** — pages, schedules, escalation policies.
- **Slack** — `#incident-<n>` channels auto-created per incident.
- **Internal runbook repo** — Markdown runbooks in version control; rendered to a wiki.
- **War-room conferencing** — Zoom + secure-room bridge.

### 16.2 Schedule

24/7 coverage per NFR IR-10. Two-tier rotation (primary + secondary). Inter-team escalation paths documented. Geographic rotation across US and EU to avoid sleep-disrupting shifts.

### 16.3 Runbook Coverage

NFR IR-08: every alert has a linked runbook. Runbooks contain:

- Triage steps (queries to run, dashboards to check).
- Likely causes.
- Mitigation procedures.
- Escalation criteria.
- Post-mortem template.

Runbooks live with the service code so they are version-controlled and updated with the service.

### 16.4 Game Days

Quarterly chaos engineering exercises (NFR IR-09):

- Pod kill in production-equivalent environment.
- AZ simulation.
- Dependency failure (Stripe down; Twilio down; SAML IdP down).
- KMS rate-limit simulation.

Each game day surfaces gaps in runbooks, monitoring, or automation; gaps become Phase 2 / 4 work tickets.

---

### 17. Customer-Facing Observability

### 17.1 Status Page (status.qeetify.com)

- Independently hosted (NFR AV-10) — not on Qeet ID infrastructure (a Qeet ID outage cannot take down the status page).
- 99.99% uptime SLA on the status page itself.
- Live incident status, historical incidents, scheduled maintenance.
- RSS / webhook subscription for tenants.

### 17.2 Public Uptime Metrics

- Monthly platform uptime % per service tier.
- Historical SLA compliance.
- Last 90 days at-a-glance.

### 17.3 In-Dashboard Observability for Tenants

- Per-tenant uptime
- Per-tenant API latency
- Per-tenant login funnel
- Per-tenant rate-limit consumption

These are part of the differentiation story — transparent operations.

### 17.4 Customer Communication on Incidents

Per NFR IR-04, status page updated within 15 min of P1 declaration. Customer-affecting P2 also posted. Post-mortem summary within 7 days for P1 (NFR IR-07).

---

### 18. Performance & Cost of Observability

Observability is not free. We track:

- Log volume per service (Loki ingestion).
- Cardinality (active series count in Prometheus).
- Trace volume (Tempo ingestion).
- Storage cost in S3 cold tiers.

Cost monitoring of the observability stack is part of the broader cost dashboard. A target — observability cost ≤ 5% of total infra cost — is monitored.

---

### 19. Open Decisions Carried From This Document

| # | Question | Owner | Target |
| --- | --- | --- | --- |
| OQ-OBS-01 | Logging stack — Loki vs ELK | SRE Lead | Phase 2 close |
| OQ-OBS-02 | Tracing backend — Jaeger vs Tempo | SRE Lead | Phase 2 close |
| OQ-OBS-03 | Synthetic monitoring — self-hosted vs Checkly | SRE Lead | Phase 2 close |
| OQ-OBS-04 | RUM tool — Grafana Faro vs Datadog RUM vs Sentry | DX + SRE | Phase 2 close |
| OQ-OBS-05 | Status page — Statuspage.io vs self-hosted | Product + SRE | Phase 2 close |
| OQ-OBS-06 | Long-term metrics store — Mimir vs Thanos vs hosted Grafana Cloud | SRE Lead | Phase 2 close |
| OQ-OBS-07 | Datadog as a secondary surface — adopt at MVP vs later | CTO + Finance | Phase 2 close |

---

### 20. Approvals & Sign-off

| Role | Name | Signature | Date |
| --- | --- | --- | --- |
| SRE Lead |  |  |  |
| DevOps / Cloud Architect |  |  |  |
| Solution Architect |  |  |  |
| Security Architect |  |  |  |
| Compliance Officer (audit pipeline) |  |  |  |
| Backend Engineering Lead |  |  |  |
| CTO |  |  |  |

---

*This document is version controlled. The observability stack and SLO catalogue are living artefacts — SLOs are reviewed quarterly with the SRE Lead; alert thresholds are tuned monthly; new services must register their dashboards and runbooks before reaching production.*

---

**Qeet ID — Authenticate Everything.** *A Qeet Group Company*
