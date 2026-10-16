# Workflows — qeet-id-server

**Level:** L2 — repository · **Last verified:** 2026-08-28
**Verification scope:** every command below was checked against the `Makefile` and
`.github/workflows/ci.yml`. Every path was confirmed to exist.

Step-by-step for the changes made most often here. For *where* things are, see
[architecture-map.md](architecture-map.md). For *what must not change*, see
[boundaries.md](boundaries.md).

---

## Set up locally

```bash
make install          # go mod download
cp .env.example .env  # placeholders work for local development
make db-up            # postgres :5001 · nats :4222 · mailpit :8025
make dev-secrets      # local JWT + SAML keys into .secrets/
make migrate-up       # apply migrations (repeat, or let `make dev` embed-apply them)
make seed             # demo tenants and users
make dev              # API on :4001
```

Caught email is readable at `http://localhost:8025` (mailpit). Nothing here requires access to
staging or production.

---

## Add an API endpoint

```text
1  find the subsystem              docs/llm/subsystems.md — get the REAL filenames first
2  handler                         the package's http.go if it has one, else <domain>.go
3  domain logic                    same file, or a feature-named file — NOT a new service.go
4  queries.sql + regenerate        sqlc → dbgen/    (never hand-edit dbgen/)
5  wire it                         internal/bootstrap/dependencies.go
6  mount it                        internal/bootstrap/router.go
7  permission                      internal/bootstrap/permissions.go
8  OpenAPI                         api/openapi/<context>.yaml     ← CI FAILS WITHOUT THIS
9  tests                           unit + integration
10 verify                          make test && make test-integration
```

> **Step 2 matters.** The convention is `<domain>.go`, not a layered `handler/service/repository`
> split. Only four packages have a `repository.go` and only twelve have an `http.go` — creating one
> where the package does not already use that shape breaks the local pattern. Check
> [subsystems.md](subsystems.md) before adding a file.

**Decide first: public or authenticated?** `internal/bootstrap/router.go` has two `/v1` groups. The
authenticated group applies API-key resolution → `RequireAuth` → `EnforceTenantScope` → rate limits →
`rbac.Enforce`. **Putting a route in the public group opts out of all of it** — do that only for
genuinely unauthenticated endpoints, and say why in the code.

**If the route is tenant-scoped:** take the tenant from `httpx.RequireTenant(r)`, never from the
path or body, and carry `WHERE tenant_id = $1` into every query.

**The coverage gate will fail CI** if the route is not in an OpenAPI document —
`tests/integration/coverage_test.go`.

---

## Add a database change

```text
1  read the existing schema        internal/platform/database/migrations/  (+ subsystems.md)
2  new pair, next number           NNNN_description.{up,down}.sql   (highest is 0105; 0082 is absent)
3  additive first                  add columns/tables; do not drop in the same release
4  queries.sql                     update the affected domain
5  regenerate                      sqlc → dbgen/
6  service + handler
7  tests                           including tenant-scoping coverage
8  verify down migration           make migrate-down, then make migrate-up
```

**Never edit an applied migration.** Fix forward with a new pair.

**Expand → migrate → contract.** A migration that drops or renames a column ships **at least one
release after** the code that stopped using it, or a rollback breaks.

**New tenant-scoped table?** It needs a `tenant_id` column and every query needs the predicate.
There is no RLS to catch a mistake.

---

## Change authentication

**Security review required.**

```text
1  read the product flow           qeet-id-context/FLOWS/authentication.md  (what it should do)
2  find the implementation         internal/access/{authentication,passkeys,mfa,recovery}/
3  check session/token impact      does it change qe_ls, qe_td, or token claims?
4  check API impact                api/openapi/auth.yaml
5  security review                 SECURITY.md + qeet-context/SECURITY.md
6  tests                           unit + tests/security/ + integration
7  cross-repo                      qeet-id-context/CHANGE-MATRIX.md
```

**Never weaken** enumeration safety, lockout, hashing parameters, or challenge TTLs. Password hashing
is Argon2id — changing parameters is a security change, not tuning.

**If token claims change, stop.** That reaches every Qeet product and every external relying party.
Escalate before implementing.

---

## Change authorization

**Security review required.**

```text
1  identify the model              rbac · abac · rebac · authzen
2  internal/access/authorization/<model>/
3  route permissions               internal/bootstrap/permissions.go
4  tenant implications             does it change what crosses a tenant boundary?
5  console impact                  a new permission needs UI work — the console is UX-only
6  tests                           MUST include a cross-tenant denial test
7  verify                          make test && make test-integration
```

**Remember:** route-level RBAC applies to **user JWTs only**. API keys and service principals bypass
it and are bounded by their encoded scopes. A permission change may not affect machine callers at
all — check both paths.

**ABAC fails closed** by design. Do not "fix" a denial by loosening the evaluator.

---

## Change tenant isolation

**The highest-risk change in this repository. Security review is mandatory.**

```text
1  read                            docs/llm/context.md § Tenant isolation
2  internal/platform/http/httpx/auth.go        RequireTenant, EnforceTenantScope
3  internal/bootstrap/router.go                where the guard is applied
4  every affected queries.sql                  the predicate
5  tests                            cross-tenant denial, at every layer touched
6  report, do not resolve           any gap goes to qeet-id-context/DRIFT-REGISTER.md
```

**Restructuring the chi route tree counts as a tenant-isolation change** — the guard depends on
nested-route matching and fails **open** if the routes are flattened. It looks like a refactor. It
is not.

**Do not add RLS as a side effect of another task.** It is a recorded future improvement and needs
its own decision.

---

## Add a background job

```text
1  sync or async?                  async if retryable, slow, or must survive the request
2  existing pattern                internal/platform/jobs/worker.go
3  event-driven?                   write to the outbox in the SAME transaction as the state change
4  register it                     cmd/worker/main.go and/or embedded in the API
5  scheduled instead?              cmd/scheduler — advisory-lock coordinated, safe on N replicas
6  retry + dead-letter             follow internal/developer/webhooks/
7  observability                   metrics and structured logs — no PII
8  tests
```

**Jobs must be idempotent.** Delivery is at-least-once and retries are real.

**Tenant scope does not come for free in a worker.** There is no request principal — carry the
tenant explicitly through the job payload.

---

## Change OAuth / OIDC

**Security *and* interoperability review. The widest blast radius in the repository.**

```text
1  read                            qeet-id-context/FLOWS/oauth-oidc.md
2  internal/federation/oidc/
3  discovery impact                does the discovery document change? → every RP
4  claims impact                   → EVERY Qeet product and external RPs
5  spec conformance                cite the RFC; do not improvise
6  api/openapi/federation.yaml
7  tests                           integration, incl. tests/integration/signing_keys_test.go
8  cross-repo                      qeet-id-context/CHANGE-MATRIX.md — coordinate BEFORE merging
```

There are **two token endpoints** — `/v1/oauth/token-code` (all OIDC grants) and `/v1/oauth/token`
(`client_credentials` only). Know which you are changing.

---

## Change federation (SAML / SCIM / LDAP / social)

**Security *and* protocol-compatibility review. External consumers cannot be surveyed.**

```text
1  find the subsystem              docs/llm/subsystems.md#federation
2  internal/federation/<protocol>/
3  parser safety                   SAML XML, SCIM payloads and LDAP responses are UNTRUSTED input
4  spec conformance                cite the RFC or the SCIM/SAML profile — do not improvise
5  api/openapi/federation.yaml
6  tests                           unit + the mapped integration test
7  external impact                 a customer's Okta/Entra tenant is configured against this
```

**SCIM deprovisioning is how an enterprise revokes access when someone leaves.** Breaking it silently
is a security incident, not a bug.

SCIM errors deliberately use the **RFC 7644** envelope rather than Qeet's standard error shape, and
SAML deviates on success paths. Both are correct — protocol compliance beats house style. Do not
"normalise" them.

Additive only, or a deprecation window with direct customer notice. See
`qeet-id-context/CHANGE-MATRIX.md`.

---

## Refactor

```text
1  behaviour must not change       if it changes, it is not a refactor
2  respect R1/R2                   tests/architecture/arch_test.go will fail otherwise
3  wiring stays in bootstrap
4  no cross-context concrete imports
5  make test                       architecture fitness runs here
6  git diff                        confirm no behavioural change slipped in
```

**Never restructure the route tree as part of a refactor** — see the tenant-isolation workflow.

---

## Update a dependency

```bash
go get -u <module> && go mod tidy
go build ./... && go test -race ./...
```

CI runs `govulncheck`. A new dependency in an authentication, cryptography or payment path needs
review before merge.

---

## Finish any task

```bash
go build ./...
go test -race ./...        # includes architecture fitness
make lint                  # go vet — NOT the CI lint
git diff                   # no secrets, no unrelated changes, no dbgen hand-edits
```

If the change touched a route, also:

```bash
make test-integration      # includes the OpenAPI route-coverage gate
```

**`make lint` is `go vet` only.** CI additionally runs `golangci-lint` v2.14.0 with `errcheck`,
`staticcheck` and `misspell` on new code. Passing locally does not guarantee CI passes.

### Ask before proceeding if the change would

- weaken any security control, or bypass `EnforceTenantScope`
- edit an already-applied migration
- change JWT claims, signing, or `kid` handling
- change SCIM, SAML or webhook contracts
- restructure the chi route tree
- require modifying another repository
