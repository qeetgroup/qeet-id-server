# api/openapi/

The Qeet ID REST contract: **five self-contained, bounded-context OpenAPI 3.1
documents**, one per bounded context of `internal/` and named for it. There is no monolithic
`openapi.yaml`.

| File                               | Context    | Surface                                                                                              |
| ---------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------- |
| [access.yaml](access.yaml)         | access     | Login/session, RBAC, ReBAC, MFA, passkeys, IP rules, auth/security policy, threats                   |
| [identity.yaml](identity.yaml)     | identity   | Users, organizations, groups, invites, verification, branding, domain verification                   |
| [federation.yaml](federation.yaml) | federation | OIDC, SAML, SCIM, LDAP, social login                                                                 |
| [developer.yaml](developer.yaml)   | developer  | API keys, webhooks, secrets vault, verifiable credentials, auth hooks, agents                        |
| [operations.yaml](operations.yaml) | operations | Audit, analytics, billing, GDPR, email templates, retention, log sinks (SIEM), notifications, health |

**These five files are generated — edit [`src/`](src/), then run `make openapi`.**
They are committed because the Go tests, the api.qeet.in portal (qeet-apis) and the
SDK contract checks read them directly. Each one is standalone: it carries every
component its paths use, and every `$ref` in it points inside the same file.

## The sources

```
src/
├── shared/                         definitions used by more than one document
│   ├── schemas/  responses/  parameters/  securitySchemes/
├── developer/                      one folder per document (access, identity, …)
│   ├── openapi.yaml                info, servers, tags, and the ordered list of paths
│   ├── paths/<tag>/<path>.yaml     one file per path, holding all of its methods
│   └── components/<section>/       definitions only this document uses
├── redocly.yaml                    the lint rules (all of them; each fails the build)
├── .redocly.lint-ignore.yaml       reviewed exceptions, each with its reason
├── package.json, bun.lock          Redocly CLI, pinned
```

- **One file per path.** `/v1/organizations/{organizationID}/webhooks` lives in
  `developer/paths/webhooks/v1_organizations_{organizationID}_webhooks.yaml`: the path with `/`
  turned into `_`, in a folder named after its operations' tag.
- **A component's file name is its name.** `shared/schemas/TokenPair.yaml` becomes
  `#/components/schemas/TokenPair` in every document that uses it, so keep file names
  exactly as the component should be called.
- **Shared or local.** A definition used by one document lives in its `components/`;
  one used by several lives once in `shared/`. Never define the same name in both
  places: the portal merges the five documents and keeps only the first copy of a name.
- **Reference files, not anchors.** Write `$ref: ../../components/schemas/Agent.yaml`
  (a relative file path). The bundler turns it into `#/components/schemas/Agent`. A
  definition nothing references is left out of the bundle.
- **operationId.** lowerCamelCase, verb first, unique across the five documents (lint
  and the consistency test enforce both): `list…` and `get…` for GET, `create…`,
  `update…` (PATCH) and `set…` (PUT), `delete…` — or the summary's own verb where it
  says more (`revoke`, `remove`, `disable`, `rotate`, `verify`…). Acronyms are words
  (`getOidcClient`); `My` marks the caller's own resource where an administrator's
  version exists (`listMySessions`, `listUserSessions`). Once the first release is out an
  operationId never changes: generated SDKs use it as the method name.
- **Lists.** A list answers `{items, …}` in one of two ways. Either it pages by cursor:
  a `limit` parameter, `$ref: …/shared/parameters/Cursor.yaml`, and a `next_cursor`
  property (`shared/schemas/NextCursor.yaml`), built server-side with
  `paging.ParseCursor`, `paging.Next` and `paging.Page`. Or it answers at most 1,000
  items and a `truncated` property (`shared/schemas/Truncated.yaml`), with its query
  reading `LIMIT 1001` and the handler answering `paging.List`. The consistency test fails
  on a list that does neither, outside the few catalogues in `unpagedLists`.
- **IDs.** `{organizationID}` is always `$ref: …/shared/parameters/OrganizationID.yaml`. Give any
  other path ID `format: uuid` when its handler parses it with `uuid.Parse`, and only
  then: provider names, template keys and similar stay plain strings.
- **Headers.** Every response component declares `X-Request-Id`
  (`shared/headers/RequestId.yaml`). A route in `NoStoreRoutes()` declares
  `Cache-Control` and `Pragma` on its success answers, and a route in
  `IdempotentRoutes()` takes the `IdempotencyKey` parameter and declares
  `Idempotent-Replayed` (`internal/bootstrap/router.go` holds both lists).
- **Examples.** Use made-up data: `example.com` addresses, `FAKE` in tokens and
  signatures, `203.0.113.x` addresses, and IDs that look real but aren't. Lint checks
  every example against its schema, including fields the schema doesn't define.

## Adding or changing routes

1. Add or edit the path file under `src/<document>/paths/<tag>/`. A new path also gets
   a line in `src/<document>/openapi.yaml`, next to the other paths of its tag.
2. Run `make openapi` to rebuild the five documents, and commit sources and documents
   together, in the same change as the route.
3. Run the tests in `internal/bootstrap/` (they run in `make ci`):
   - [`openapi_coverage_test.go`](../../internal/bootstrap/openapi_coverage_test.go)
     reads the **union** of the documents and walks the exact production mount
     helpers. It fails on undocumented routes, stale operations, and API-auth
     security mismatches.
   - [`openapi_valid_test.go`](../../internal/bootstrap/openapi_valid_test.go) validates
     each document as OpenAPI 3.1.
   - [`openapi_consistency_test.go`](../../internal/bootstrap/openapi_consistency_test.go)
     fails when a component name is defined differently in two documents, an operationId
     is missing or used twice, an operation has no tag or an undeclared one, tags first
     appear in a different order from the document's `tags:` array, the no-store and
     idempotency headers disagree with the routes that send them, or a list neither pages
     by cursor nor declares `truncated`.

`make openapi-check` (also in `make ci`) first lints the sources, then rebuilds the
documents into a temporary directory and fails if any committed document differs from
what its sources build, so a hand edit to a generated file, or a source change without
`make openapi`, is caught. Both targets need [Bun](https://bun.sh); Redocly runs on it,
with telemetry off.

## Lint

[`src/redocly.yaml`](src/redocly.yaml) lists every rule; there is no preset, and each
rule fails the build. They check that references resolve, every operation is named,
described, tagged and secured and has a success (2XX or 3XX) and an error (4XX) answer,
schemas don't contradict themselves, and examples match their schemas. The file also
says which rules are left out and why. This is OpenAPI 3.1: write a nullable field as
`type: [string, 'null']`, not `nullable: true`, which 3.1 tools ignore.

An exception goes in [`src/.redocly.lint-ignore.yaml`](src/.redocly.lint-ignore.yaml)
with its reason, only once you have checked the server really behaves that way. Checks
across the five documents (one definition per name, unique operationIds, tag order) are
in `openapi_consistency_test.go`, since the linter reads one document at a time.

## Tag order and the developer journey

Operations are grouped by `tag`, and the **order of paths in each `openapi.yaml` is
intentional**. The api.qeet.in portal (Scalar) orders the tags within a product by
the **first appearance of each tag in document order** — it does _not_ read the
root `tags:` array order or any `x-*` ordering hint. Each document's paths are therefore
laid out to follow an onboarding journey, and its top-level `tags:` array lists the
tags in that same order (the consistency test enforces it):

- **auth**: Auth → Passkeys → MFA → RBAC → ABAC → ReBAC → AuthZEN → Auth Policy → Policy → IP Rules → Threats
- **management**: Organizations → Domains → Users → Verification → Groups → Invites → Branding
- **federation**: OIDC → Social → SAML → OIDC Connections → LDAP → Directory → SCIM → Admin Portal
- **developer**: API Keys → Agents → Credentials → Auth Hooks → Webhooks → Secrets → Token Vault
- **operations**: Health → Activity → Analytics → Search → Audit → Compliance → Data Retention → GDPR → Log Sinks → Notifications → Rate Limits → Email Templates → Qeet AI → Billing → Entitlements → Sales

When adding an operation, list its path next to the other paths of its tag so the
journey order is preserved, and declare the tag (with a `description`) in the
top-level `tags:` array.

## Versioning

The five documents share one `info.version`. Until the first release it stays `0.2.0`, while the
contract can still change. From then on it is the version of the release the documents describe
(`2027.1.0`, then each later release's), so a document always says which release it belongs to. The
path carries the promise to callers: within `/v1` a release only adds (routes, optional fields,
response fields, error codes), and a change that would break a caller needs a new `/v2`.

## Consumers

A consumer that wants one document merges the five itself — the qeet-apis reference
site does so in `scripts/sync-specs.mjs`.
