# qeet-id backend — Architecture & Conventions

Module: `github.com/qeetgroup/qeet-id` (rooted at the repo root). A Go **modular
monolith**: one package per domain under [domains/](../domains/), grouped by
bounded context, a single entrypoint ([cmd/server/main.go](../cmd/server/main.go)),
chi v5 routing, PostgreSQL via pgx v5. This file is the reference new code conforms
to — CI and review enforce it.

## Package layout

Each domain is a package under `domains/<context>/<domain>` where context is one of
`identity` / `access` / `federation` / `developer` / `operations` (e.g.
`domains/access/authentication` = `package auth`, `domains/federation/oidc`,
`domains/access/authorization/rbac`, `domains/identity/users`, …). Folder names are
domain-oriented; the Go package clause keeps its short name. Cross-cutting
infrastructure lives under `platform/*` (`errs`, `httpx`, `logger`, `metrics`,
`tracing`, `health`, `buildinfo`, `db`, `paging`, `notifier`, `ratelimit`, …).

**Gold-standard domain shape — the `tenant` triplet:**
- `domain.go` — exported types + input structs (the domain model).
- `repository.go` — persistence (`Repository`/`Service` over a `*pgxpool.Pool`).
- `http.go` — the `Handler`, its `Mount`, and HTTP glue.

Cross-domain calls go through **small interfaces declared by the consumer**, not by
importing another domain's concrete service (see `tenant.tokenIssuer`,
`saml.SessionResolver`). This keeps the dependency graph acyclic. New domains follow
this shape; large protocol handlers (`oidc`, `saml`, `scim`) may split by concern
(`core.go`/`device.go`/`admin.go`) but keep the same conventions.

## Error handling — one envelope

Every HTTP error goes through [platform/errs](platform/errs/errs.go)
+ `httpx.WriteError`. Handlers return/raise an `*errs.Error` (or a sentinel:
`ErrBadRequest`, `ErrUnauthorized`, `ErrForbidden`, `ErrNotFound`, `ErrConflict`,
`ErrUnprocessable`, `ErrTooManyRequests`, `ErrInternal`, `ErrNotImplemented`) and call
`httpx.WriteError(w, r, err)`. The JSON shape is stable:

```json
{ "error": { "code": "...", "message": "...", "detail": "...", "request_id": "..." } }
```

- **Do not** use `http.Error` for API responses — it emits plain text and breaks the
  envelope (the SAML handlers were converted away from it).
- `httpx.WriteError` maps a known `*errs.Error` to its status; any other error logs as
  `unhandled error` and returns `500`. So pass a raw `err` only when `500 + log` is what
  you want; otherwise wrap with an `errs` sentinel + `.WithDetail(...)`.

**Documented deviations (intentional):**
- SAML **success** paths return SAML XML (metadata) or a 302 redirect / auto-submit
  HTML form (the POST binding) — these are browser/IdP-facing, not JSON. SAML *errors*
  use the JSON envelope.
- **SCIM** (`/scim/v2`) uses the RFC 7644 error envelope (`schemas`/`status`/`detail`)
  via `writeSCIM`, not the qeet envelope — required for IdP compatibility.

## Logging

Structured `slog` only; the default logger wraps a redacting handler
([platform/logger](platform/logger/)). Use key/value pairs
(`slog.Error("saml acs: provisioning failed", "err", err, "connection", id)`), never
string interpolation, and never `fmt.Println`. JSON response encoding is centralized in
`httpx.WriteJSON`, which logs encode failures — prefer it over hand-rolled encoders
(SCIM's `writeSCIM` logs likewise).

## Config

All configuration is centralized in [platform/config/config.go](platform/config/config.go)
via `envconfig`. No scattered `os.Getenv`. `Config.Validate()` is the production boot
gate: outside `SERVICE_ENV=dev` it refuses to start on insecure defaults (weak
`JWT_SECRET`, missing signing/secret keys, wildcard origins, localhost base URL, CSRF
disabled). New required prod inputs belong in `Validate()`.

## Persistence

- **Hand-written SQL over pgx v5 is the canonical data-access path.** Repositories own
  their queries; multi-tenant tables are always scoped by `tenant_id`.
- `sqlc` is configured (`sqlc.yaml`, generated `platform/sqlcgen`) but is **not**
  the active path today. Full sqlc adoption is a deferred, separate effort — do not
  introduce a sqlc/hand-written split within a domain; match the surrounding code.
- Migrations are golang-migrate SQL pairs in [migrations/](migrations/). **Never edit an
  applied migration — add a new pair.** The deploy migration image is
  [Dockerfile.migrate](Dockerfile.migrate).

## Timeouts & context

`context.Context` propagates from the request through services to the DB. Outbound
network clients must be bounded:
- HTTP egress (`webhook`, `hibp`, `notifier/twilio`, `social/oauthclient`) uses
  `http.Client{Timeout: …}`.
- SMTP (`notifier/smtp.go`) dials with `net.Dialer{Timeout}` + `DialContext` and caps the
  exchange with a connection deadline (`net/smtp.SendMail` does neither — don't use it).

## HTTP surface

- Versioned API under `/v1`; protocol/well-known surfaces at their spec'd paths
  (`/.well-known/*`, `/scim/v2`, `/saml/*`).
- List endpoints paginate via [platform/paging](platform/paging/).
- Middleware order (see [platform/http/router.go](platform/http/router.go)): RequestID →
  RealIP → Recoverer → InFlight → SecurityHeaders → AccessLog → Tracing → Metrics → CSRF
  → CORS.
- **OpenAPI guard:** [platform/http/openapi_coverage_test.go](platform/http/openapi_coverage_test.go)
  fails if any mounted route is absent from [api/openapi.yaml](api/openapi.yaml). Add new
  routes to the spec in the same change.

## Observability & build

- Metrics at `/metrics`, probes at `/healthz`/`/readyz`
  ([platform/health](platform/health/)), OTel tracing gated by
  `OTEL_EXPORTER_OTLP_ENDPOINT`.
- Build metadata is stamped via `-ldflags` into
  [platform/buildinfo](platform/buildinfo/) and surfaced on `/healthz`
  + the `build_info` metric. See [../deploy/](../deploy/) for the deploy/release story.

## Deferred / out of scope (tracked, not yet done)
Full sqlc adoption; physically splitting the large `mfa.go` / `oidc.go` handlers;
ReBAC / token-exchange / CIBA; multi-cloud KMS (AWS only today).
