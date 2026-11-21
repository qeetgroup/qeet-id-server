# Workflows — qeet-id-server

**Level:** L2 — repository · **Last verified:** 2026-11-15
**Verification scope:** every command below was checked against the `Makefile` and
`.github/workflows/ci.yml` at `c2454fec`. Every path was confirmed to exist.

Step-by-step for the changes made most often here. For _where_ things are, see
[architecture-map.md](architecture-map.md). For _what must not change_, see
[boundaries.md](boundaries.md).

---

## Set up locally

```bash
make install          # go mod download
cp .env.example .env  # then set DB_URL's password to `password` for docker-compose.yml
make db-up            # postgres :5001 · nats :4222 · mailpit :8025
make dev-secrets      # local JWT + SAML keys into .secrets/
make seed             # demo organizations and users (applies the migrations first, as `make dev` does)
make dev              # API on :4001
```

Caught email is readable at `http://localhost:8025` (mailpit). Nothing here requires access to
staging or production.

---

## Add an API endpoint

```text
1  find the subsystem              docs/llm/subsystems.md — get the REAL filenames first
2  handler                         the package's http.go
3  domain logic                    <package>.go or the topic's file — NOT a new service.go
4  queries.sql + regenerate        make sqlc → dbgen/ (a new package: add its entry to sqlc.yaml; never hand-edit dbgen/)
5  wire it                         internal/bootstrap/wire_<context>.go (new<Context>, wire<Context>, <context>Handlers)
6  mount it                        internal/bootstrap/router.go
7  permission                      <context>Permissions in internal/bootstrap/wire_<context>.go (step-up: <context>StepUps)
8  OpenAPI                         api/openapi/src/<context>/paths/<tag>/ + make openapi  ← LOCAL TEST GATE FAILS WITHOUT THIS
9  tests                           unit
10 verify                          make test
```

> **Step 2 matters.** Every package has the same shape (`<package>.go`, `http.go`, `errors.go`, one file
> per topic), not a layered `handler/service/repository` split. Only three packages (rbac, organization, user) also have a `service.go` or `repository.go`: don't add one elsewhere. Check
> [subsystems.md](subsystems.md) before adding a file.

**Decide first: public or authenticated?** `internal/bootstrap/router.go` has two `/v1` groups. The
authenticated group applies API-key resolution → `RequireAuth` → `EnforceOrganizationScope` → rate limits →
`rbac.Enforce`. Authenticated routes take a bearer token or API key only; the hosted login's session
cookie is accepted just on the short `LoginSessionRoutes()` list in the same file. **Putting a route in the public group opts out of all of it** — do that only for
genuinely unauthenticated endpoints, and say why in the code.

**If the route is organization-scoped:** take the organization from `httpx.RequireOrganization(r)`, never from the
path or body, and carry `WHERE organization_id = $1` into every query.

**The coverage test will fail** if the route is not in an OpenAPI document —
`internal/bootstrap/openapi_coverage_test.go`. Add the path file under `api/openapi/src/`, list it
in that document's `openapi.yaml` next to its tag's other paths, and run `make openapi`
(`api/openapi/README.md`). It runs in the local `make ci` gate and in hosted
Verify, which runs the API contract checks but not the other Go test suites.

A new authenticated route **refuses access tokens issued to applications** (they carry `client_id`)
by default: they are for the application's own use, not account or organization management. Only routes
meant for applications belong in `bootstrap.ApplicationTokenRoutes()` (pinned by a test). Its policy in
`bootstrap.RoutePolicies()` also names the scope an application's token needs there
(`ApplicationScope`: the permission on an administrative route, `account.read`/`account.write` on the
user's own account); a route without one fails `TestEveryRouteNamesAnApplicationScope`.

---

## Add a database change

```text
1  read the existing schema        internal/platform/database/migrations/  (+ subsystems.md)
2  new pair, next number           NNNN_description.{up,down}.sql   (read the highest with ls; 0001–0012 are the baseline)
3  additive first                  add columns/tables; do not drop in the same release
4  queries.sql                     update the affected domain
5  regenerate                      sqlc → dbgen/
6  service + handler
7  tests                           including organization-scoping coverage
8  apply it                        make migrate-up (or make dev, which applies it at start)
9  verify down migration           make migrate-down, then make migrate-up (it applies the migration again)
10 changed it after it ran?        the same: make migrate-down, edit, make migrate-up (only while it is unmerged)
```

**Never edit an applied migration.** Fix forward with a new pair.

**Expand → migrate → contract.** A migration that drops or renames a column ships **at least one
release after** the code that stopped using it, or a rollback breaks.

**A build refuses a database newer than itself.** Start (`migrations.Run`), the scheduler, the worker
and `qeet-id-server schema-check` (run by the host before it switches versions) refuse a database a
later release has migrated past the build's newest migration, a half-applied one, and one whose applied
migrations aren't recorded as the files the build carries, with the recovery step
(`migrations.SchemaError`). So rolling back to a release from before a migration means a
restore or a roll forward, never an automatic down-migration.

**New organization-scoped table?** It needs an `organization_id` column, every query needs the predicate, and its
migration needs `ENABLE ROW LEVEL SECURITY` and the `organization_isolation` policy (copy one from 0011),
unless it holds a person's own data across organizations — then list it in `accountLevelTables`
with why. `TestOrganizationTablesHaveRowSecurity` fails otherwise. A new schema needs its grants to
`qeet_app` too.

---

## Change authentication

**Security review required.**

```text
1  read the product flow           qeet-id-context/FLOWS/authentication.md  (what it should do)
2  find the implementation         internal/access/{authentication,passkey,mfa,recovery}/
3  check session/token impact      does it change qe_ls, qe_td, or token claims?
4  check API impact                api/openapi/src/access/
5  security review                 SECURITY.md + qeet-context/SECURITY.md
6  tests                           unit
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
3  route permissions               <context>Permissions in internal/bootstrap/wire_<context>.go
4  organization implications             does it change what crosses an organization boundary?
5  console impact                  a new permission needs UI work — the console is UX-only
6  tests                           MUST include a cross-organization denial test
7  verify                          make test
```

**Remember:** every authenticated route has one `RoutePolicy`. Users need the named role permission;
API keys, service principals and agents must be admitted by actor type and carry one of the route's
machine scopes (unless the policy explicitly delegates a resource-derived scope check to the
handler). Application-issued user tokens need both the user's permission and the route's approved
OAuth scope. Check every caller type when a permission changes.

**ABAC fails closed** by design. Do not "fix" a denial by loosening the evaluator.

---

## Change organization isolation

**The highest-risk change in this repository. Security review is mandatory.**

```text
1  read                            docs/llm/context.md § Organization isolation
2  internal/platform/http/httpx/auth.go        RequireOrganization, EnforceOrganizationScope
3  internal/bootstrap/router.go                where the guard is applied
4  every affected queries.sql                  the predicate
5  tests                            cross-organization denial, at every layer touched
6  report, do not resolve           record product-level drift in qeet-id-context and its changelog
```

**Restructuring the chi route tree counts as an organization-isolation change** — the guard depends on
nested-route matching and fails **open** if the routes are flattened. It looks like a refactor. It
is not.

**Don't widen `postgres.AcrossOrganizations` as a side effect of another task.** A request runs across
organizations only where it must, and checks the caller's right to each organization itself.

---

## Add a background job

```text
1  sync or async?                  async if retryable, slow, or must survive the request
2  existing pattern                internal/platform/worker/worker.go
3  event-driven?                   write to the outbox in the SAME transaction as the state change
4  register it                     the workers list in bootstrap/dependencies.go (the API runs it)
5  scheduled instead?              a job function in its context's wire_<context>.go, listed in bootstrap.MaintenanceJobs — once per interval across instances
6  retry + dead-letter             follow internal/developer/webhook/
7  observability                   metrics and structured logs — no PII
8  tests
```

**Jobs must be idempotent.** Delivery is at-least-once and retries are real.

**Organization scope does not come for free in a worker.** There is no request principal — carry the
organization explicitly through the job payload.

---

## Change OAuth / OIDC

**Security _and_ interoperability review. The widest blast radius in the repository.**

```text
1  read                            qeet-id-context/FLOWS/oauth-oidc.md
2  internal/federation/oidc/
3  discovery impact                does the discovery document change? → every RP
4  claims impact                   → EVERY Qeet product and external RPs
5  spec conformance                cite the RFC; do not improvise
6  api/openapi/src/federation/ + make openapi
7  tests                           unit
8  cross-repo                      qeet-id-context/CHANGE-MATRIX.md — coordinate BEFORE merging
```

There is **one token endpoint**, `POST /v1/oauth/token` (`http_token.go`), for every grant, chosen by
`grant_type`: the applications' grants and `client_credentials` for service principals and agents
(`MachineClient`, wired in `bootstrap`). Device and CIBA polling share one step, `pollToken`
(`poll.go`). A refusal goes through the one RFC 6749 §5.2 writer, `writeTokenError`.

---

## Change federation (SAML / SCIM / LDAP / social)

**Security _and_ protocol-compatibility review. External consumers cannot be surveyed.**

```text
1  find the subsystem              docs/llm/subsystems.md#federation
2  internal/federation/<protocol>/
3  parser safety                   SAML XML, SCIM payloads and LDAP responses are UNTRUSTED input
4  spec conformance                cite the RFC or the SCIM/SAML profile — do not improvise
5  api/openapi/src/federation/ + make openapi
6  tests                           unit
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
2  respect R1–R6                   make lint fails otherwise (depguard)
3  wiring stays in bootstrap
4  no cross-context concrete imports
5  make test
6  git diff                        confirm no behavioural change slipped in
```

**Never restructure the route tree as part of a refactor** — see the organization-isolation workflow.

---

## Update a dependency

```bash
go get -u <module> && go mod tidy
go build ./... && go test -race ./...
```

CI runs `govulncheck`. A new dependency in an authentication, cryptography or payment path needs
review before merge.

---

## Add a feature to the demo data

The demo data (`cmd/seed`) is how people test end to end: every console and hosted-login screen
should have something real to show. When a change adds a feature, a table or a screen, extend the
seed in the same change.

1. **Find its step.** `main.go` runs five, each a package under `cmd/seed/internal/`:

   | Step           | What it seeds                                                                                                                                         |
   | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
   | `census`       | Organizations, plans, people, roles, groups (`orgs.go` is the cast: who, where, which plan and features)                                              |
   | `accounts`     | Branding, domains, policies, templates, invitations, suspensions, data requests, access requests, notifications                                       |
   | `connections`  | Applications and their grants, single sign-on (SAML, OpenID Connect), group mappings, break-glass, LDAP, SCIM, social sign-in, enterprise-setup links |
   | `integrations` | API keys, service principals, agents, secrets, token vault, credentials, ABAC and ReBAC, rate limits, auth hooks, log streaming, webhooks             |
   | `security`     | Second factors, address rules, risk and bot settings, sign-ins, attacks, anomaly settings, compliance, status incidents, sales leads                  |

2. **Write only through the server.** Call a service (`w.Deps.<Handler>.Service`) or, where the
   console's request does more than the service (an audit record, a check), the handler itself with
   `w.API.Do` (SCIM with `w.API.SCIM`). No SQL of any kind: a state no service or handler can reach
   is left out. Import server logic; never copy it.
3. **Nothing is backdated.** Everything is stamped when it is written, so a state that only time
   reaches (an expired invitation, a past-due renewal, a completed erasure) can't be seeded.
4. **Choose the people the product would.** Use the helpers (`o.Admin`, `o.First`, `actorOn`,
   `issuer`) and respect the rules: an administrator acts on someone only if they hold every
   permission that person holds, a credential carries only scopes its creator holds, and a deny
   policy on an attribute the request lacks refuses.
5. **Keep it real but harmless.** Qeet Group's products and `qeet.in` addresses are real. Customers
   are invented, on domains that don't resolve, so no seeded email, webhook or sign-in reaches a
   real company. Client secrets and subjects are in each vendor's own format. No real person's
   data. Every account shares one password.
6. **Tell the tester.** Add a `w.Note(section, ...)` line for anything worth trying, and set
   `Login` on a fixed person in `census` when an account demonstrates something.
7. **Check it.** `make seed-reset`, then count the rows in every table, and run `make lint`.

In the kit's DEV the same seed runs with `bash macos/dev/seed.sh` (Windows: `.\windows\dev\seed.cmd`).
It replaces everything in DEV. TEST and STAGING never have it.

---

## Finish any task

```bash
go build ./...
go test -race ./...        # includes the OpenAPI route-coverage gate
make lint                  # go vet + golangci-lint, as CI runs it
make test-db               # if you touched SQL, organization scoping or sign-in
git diff                   # no secrets, no unrelated changes, no dbgen hand-edits
```

A query on an organization-owned table must mention `organization_id`, or `internal/platform/database/organizationguard` fails `go test`;
an exception needs an allowlist line with a reason.

### Ask before proceeding if the change would

- weaken any security control, or bypass `EnforceOrganizationScope`
- edit an already-applied migration
- change JWT claims, signing, or `kid` handling
- change SCIM, SAML or webhook contracts
- restructure the chi route tree
- require modifying another repository
