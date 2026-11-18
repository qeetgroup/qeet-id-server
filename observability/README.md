# Observability

The local monitoring stack for qeet-id: metrics, logs, traces and profiles from a server you run
on your machine, with the dashboards and alerts that ship with this repository. The alert rules,
recording rules and dashboards work unchanged in a production Prometheus and Grafana.

## Run it

```bash
make db-up          # PostgreSQL, NATS and Mailpit
make obs-up         # this stack (docker compose profile "observability")
make dev-observed   # the API, with JSON logs, traces and profiles switched on
make obs-down       # stop the stack; the database stays up
```

| Open                                | For                                         |
| ----------------------------------- | ------------------------------------------- |
| Grafana, http://localhost:3300      | Dashboards, and Explore for logs and traces |
| Prometheus, http://localhost:9090   | Raw metrics, targets and rule state         |
| Alertmanager, http://localhost:9093 | Firing and silenced alerts                  |
| Pyroscope, http://localhost:4040    | CPU, memory and goroutine profiles          |
| Mailpit, http://localhost:8025      | The email each firing alert sends           |

Every port can be changed in `.env` (the development-tooling block in `.env.example` lists them).
Prometheus scrapes the API on `host.docker.internal:4001`; if you change `HTTP_PORT`, change the
`qeet-id` target in `prometheus/prometheus.yml` too.

## What goes where

| Signal   | From the API                                   | Through                                  | Stored in  |
| -------- | ---------------------------------------------- | ---------------------------------------- | ---------- |
| Metrics  | `GET /metrics` on the API port                 | Prometheus scrape, every 15s             | Prometheus |
| Probes   | `/healthz`, `/readyz`, discovery, JWKS         | blackbox exporter, scraped by Prometheus | Prometheus |
| Database | PostgreSQL statistics                          | postgres exporter, scraped by Prometheus | Prometheus |
| Logs     | JSON lines in `bin/logs/api.log`               | OpenTelemetry Collector (reads the file) | Loki       |
| Traces   | OTLP to `OTEL_EXPORTER_OTLP_ENDPOINT`          | OpenTelemetry Collector                  | Tempo      |
| Profiles | pprof on `PPROF_ADDR` (`:6060` in development) | Grafana Alloy scrape, every 15s          | Pyroscope  |
| Alerts   | rules in `prometheus/alerts.yml`, `slos.yml`   | Prometheus, then Alertmanager            | Mailpit    |

Each log line carries the request's `trace_id`: in Grafana, a log line links to its trace in Tempo,
and a trace span links back to its logs. Database queries show as spans named for their sqlc query.

| Folder            | Holds                                                             |
| ----------------- | ----------------------------------------------------------------- |
| `prometheus/`     | Scrape config, alert rules (`alerts.yml`), SLO rules (`slos.yml`) |
| `alertmanager/`   | Routing: every alert to Mailpit, grouped per alert                |
| `grafana/`        | Data sources and the three dashboards (`dashboards/*.json`)       |
| `otel-collector/` | Log file and OTLP receivers, export to Loki and Tempo             |
| `loki/`, `tempo/` | Storage settings (local disk, 7-day log retention)                |
| `alloy/`          | The profile scrape                                                |
| `blackbox/`       | The HTTP probe module                                             |

## Dashboards

- **Qeet ID — Service overview**: request rate, 5xx ratio, latency percentiles, top routes, probes,
  the two SLO budgets, and recent error and warning logs.
- **Qeet ID — Security and identity**: sign-ins by method and outcome, token requests by grant,
  rate-limit rejections, lockouts and source throttles, signing keys, revocation signals and
  audit-chain verification.
- **Qeet ID — Operations and data**: scheduled jobs, the outbox, SIEM forwarding, email, GDPR and
  retention, data-key rotation, webhook deliveries, and the database pool.

## Service level objectives

| Objective                                                         | Target | Alerts                                                           |
| ----------------------------------------------------------------- | ------ | ---------------------------------------------------------------- |
| Requests answered without a 5xx (health and metrics routes aside) | 99.9%  | `QeetIdAvailabilityBudgetBurnFast` (page), `…BurnSlow` (ticket)  |
| Sign-ins (`/v1/auth/login`) and token requests within 0.5s        | 99%    | `QeetIdSignInLatencyBudgetBurnFast` (page), `…BurnSlow` (ticket) |

The burn-rate alerts follow the multi-window method: a fast burn pages when an hour spends 2% of
the 30-day budget, a slow burn opens a ticket when the budget would run out before the month ends.

## Metrics

Besides the Go runtime (`go_*`, `process_*`), the API exports:

| Metric                                                                                                                    | Counts or measures                                                                 |
| ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `http_requests_total`, `http_request_duration_seconds`                                                                    | Requests and latency by method, route and status                                   |
| `build_info`                                                                                                              | The running version and commit                                                     |
| `sign_ins_total`                                                                                                          | Sign-ins by method and outcome (succeeded, or why refused)                         |
| `oauth_token_requests_total`                                                                                              | Token endpoint requests by grant and outcome (issued, refused, error)              |
| `rate_limit_rejections_total`                                                                                             | Requests answered 429, by limiter scope                                            |
| `sign_in_lockouts_total`, `sign_in_source_throttles_total`                                                                | Locks set by counter; source networks throttled for spraying                       |
| `sign_in_lockout_unavailable_total`                                                                                       | Password sign-ins refused because the lockout couldn't be evaluated (fails closed) |
| `sign_in_failures_unrecorded_total`, `recovery_requests_unrecorded_total`                                                 | Failures and recovery requests past the audit-trail bound                          |
| `password_hasher_rejections_total`                                                                                        | Password hashes refused because the hasher was full                                |
| `breached_password_check_allowed_on_error_total`                                                                          | Breached-password checks that couldn't reach the provider (fail open)              |
| `auth_hook_skipped_total`                                                                                                 | Sign-in hook calls that got no answer, by reason and outcome                       |
| `jwt_signing_key_active`, `jwt_signing_key_snapshot_timestamp_seconds`, `jwt_signing_key_sync_failures_total`             | The signing key in use, when the keyring was loaded, failed refreshes              |
| `session_revocation_signal_failures_total`                                                                                | Revocations whose `session.revoked` signal couldn't be queued                      |
| `audit_verify_failures_total`, `audit_verify_last_success_timestamp_seconds`                                              | Audit-chain verifications that failed; the last good one                           |
| `outbox_unpublished_events`, `outbox_oldest_unpublished_age_seconds`, `outbox_dead_letters`, `outbox_dead_lettered_total` | The event outbox backlog and dead letters                                          |
| `webhook_deliveries_total`, `webhook_pending_deliveries`, `webhook_oldest_pending_age_seconds`                            | Webhook attempts by outcome, and the backlog                                       |
| `scheduled_job_duration_seconds`, `scheduled_job_failures_total`, `scheduled_job_last_success_timestamp_seconds`          | Maintenance jobs, by job                                                           |
| `siem_forward_lag_seconds`, `siem_forward_failures_total`                                                                 | How far log sinks are behind the audit log; refused batches                        |
| `email_messages_total`                                                                                                    | Emails by template and status                                                      |
| `gdpr_erasure_failures_total`, `gdpr_organization_purge_failures_total`, `retention_user_purge_failures_total`            | Erasures and purges that failed (retried)                                          |
| `envelope_rows_on_old_keys`                                                                                               | Stored values not yet sealed with the current data key, by column                  |
| `db_pool_*`                                                                                                               | Database pool connections, acquires, waits and cancels                             |

## Alerts and what to do

Every rule's `runbook_url` points at its section below. A `critical` alert pages; a `warning` one
is worked during the day. While `QeetIdTargetDown` fires, Alertmanager holds back the warnings.

### QeetIdTargetDown

- **Means:** Prometheus has failed to scrape the API for 2 minutes. The instance is down, hung or
  unreachable.
- **Check:** `/healthz` and `/readyz` on the instance; its last log lines; the probe panel on the
  overview dashboard.
- **Act:** restart the instance if it hangs; if `/readyz` names a failing dependency (database,
  keyring), work on that dependency.

### QeetIdNoMetrics

- **Means:** no qeet-id target exists at all, so every other alert is blind.
- **Check:** Prometheus **Status › Targets**; the scrape config or service discovery.
- **Act:** restore the target. Locally, check that the API runs on the port in `prometheus.yml`.

### QeetIdHighErrorRate

- **Means:** more than 5% of requests answered 5xx for 5 minutes.
- **Check:** the overview dashboard's top routes and error logs; filter the logs on `level=ERROR`
  and follow a `trace_id` to the failing span.
- **Act:** roll back a bad release, or restore the failing dependency the traces point at.

### QeetIdHighLatencyP99

- **Means:** the slowest 1% of requests took over 1 second for 10 minutes.
- **Check:** which routes are slow (latency panel); the database pool's wait time; a CPU profile in
  Pyroscope for the same window.
- **Act:** relieve the bottleneck: pool size, a slow query (its span names the sqlc query), or load.

### QeetIdHighGoroutines

- **Means:** more than 5,000 goroutines for 10 minutes, usually a leak or calls that never end.
- **Check:** the goroutine profile in Pyroscope, grouped by function.
- **Act:** find what is piling up (often an outbound call without a deadline) and fix it; restart
  to recover meanwhile.

### QeetIdRestarting

- **Means:** in Kubernetes, the pod restarted more than twice in 15 minutes.
- **Check:** the previous container's logs (`kubectl logs --previous`); out-of-memory kills.
- **Act:** fix the crash, or raise the memory limit if the profile shows a real need.

### QeetIdAuditChainBroken

- **Means:** the scheduled verification found an audit chain that doesn't verify: rows were changed,
  removed or reordered. Treat it as a security incident.
- **Check:** `GET /v1/organizations/{organizationID}/audit/verification` for the broken chain and
  where it breaks.
- **Act:** preserve the database state, follow the security incident process, and don't repair
  rows by hand.

### QeetIdAuditVerificationStale

- **Means:** no audit-chain verification has succeeded for 6 hours.
- **Check:** `scheduled_job_failures_total` for the verify job, and its log lines.
- **Act:** fix what stops the job (database access, a timeout); run
  `POST /v1/organizations/{organizationID}/audit/verify` to confirm.

### QeetIdSessionRevocationsNotAnnounced

- **Means:** sessions ended but their `session.revoked` signals weren't queued, so applications may
  accept those tokens until they expire.
- **Check:** the metric's `reason` label and the outbox panels.
- **Act:** restore the outbox (usually the database); the revocations themselves held.

### QeetIdSigningKeySyncFailing

- **Means:** this instance can't read the shared signing-key registry, so it may refuse tokens
  signed with a rotated key.
- **Check:** `jwt_signing_key_snapshot_timestamp_seconds` per instance; database reachability.
- **Act:** restore database access; restart the instance if the keyring stays stale.

### QeetIdSignInLockoutSpike

- **Means:** more than 20 sign-in locks in 5 minutes: probably password spraying or credential
  stuffing.
- **Check:** the security dashboard's lockouts and source throttles;
  `GET /v1/organizations/{organizationID}/security/bots` for the sources.
- **Act:** block the sources at the edge or with the organization's IP rules; tell the affected
  organizations if one is targeted.

### QeetIdTokenEndpointErrors

- **Means:** the token endpoint failed with server errors for 5 minutes, so applications can't sign
  people in. Refusals such as `invalid_grant` don't count.
- **Check:** `oauth_token_requests_total{outcome="error"}` by grant; the error logs and traces for
  `/v1/oauth/token`.
- **Act:** restore the failing dependency (database, keyring); roll back a bad release.

### QeetIdWebhookBacklogStale

- **Means:** the oldest pending webhook delivery has waited over an hour.
- **Check:** `webhook_deliveries_total` by outcome; the failing subscriptions' attempts at
  `GET /v1/organizations/{organizationID}/webhooks/{id}/deliveries/{deliveryID}/attempts`.
- **Act:** if one endpoint fails, its organization fixes it, then
  `POST /v1/organizations/{organizationID}/webhooks/{id}/deliveries/retry`; if all fail, check the
  dispatcher's logs and the network egress.

### QeetIdOutboxDeadLetters

- **Means:** outbox events gave up after a day of failed publishes.
- **Check:** `outbox_dead_letters` and the publish errors in the logs.
- **Act:** fix the cause, then replay them: `scheduler replay-dead-letters [-type T] [-since RFC3339]`.

### QeetIdScheduledJobFailing

- **Means:** the scheduled job in the alert (`exported_job`) failed in the last 30 minutes.
- **Check:** that job's log lines and the operations dashboard's job panels.
- **Act:** fix the cause; the job runs again at its next slot.

### QeetIdSIEMForwardLagging

- **Means:** audit events reach an organization's SIEM more than 15 minutes late.
- **Check:** `siem_forward_failures_total`; the organization's sinks at
  `GET /v1/organizations/{organizationID}/log-sinks`, and `POST …/log-sinks/test`.
- **Act:** the organization fixes a refusing sink; if every sink lags, check egress and the job.

### QeetIdGDPRErasureFailing

- **Means:** an erasure request failed. It is retried, but it has a legal deadline.
- **Check:** the error in the logs, such as an organization's last active owner.
- **Act:** resolve the blocker with the organization, then let the sweep retry; watch the deadline.

### QeetIdAvailabilityBudgetBurnFast

- **Means:** the 5xx ratio would spend the 30-day 99.9% budget within days.
- **Check and act:** as for `QeetIdHighErrorRate`; this one catches smaller but sustained errors.

### QeetIdAvailabilityBudgetBurnSlow

- **Means:** at this rate the month's budget runs out before the month ends.
- **Act:** open a ticket; find the routes behind the 5xx ratio and fix them before it pages.

### QeetIdSignInLatencyBudgetBurnFast

- **Means:** over 14% of sign-ins and token requests took more than 0.5s in the last hour.
- **Check:** password hashing (`password_hasher_rejections_total`, CPU profile), the database pool
  and the token endpoint's spans.
- **Act:** relieve the bottleneck; more instances if hashing is the limit.

### QeetIdSignInLatencyBudgetBurnSlow

- **Means:** over 6% of sign-ins and token requests were slower than 0.5s in the last 6 hours.
- **Act:** open a ticket and work through the checks above before it pages.
