# api/openapi/

The Qeet ID REST contract, split into **five self-contained, bounded-context
OpenAPI 3.1 documents**. There is no monolithic `openapi.yaml` — these files are
the source of truth.

| File | Context | Surface |
|---|---|---|
| [auth.yaml](auth.yaml) | access | Login/session, RBAC, ReBAC, MFA, passkeys, IP rules, auth/security policy, threats |
| [management.yaml](management.yaml) | identity | Users, tenants, groups, invites, verification, branding, domain verification |
| [federation.yaml](federation.yaml) | federation | OIDC, SAML, SCIM, LDAP, social login |
| [developer.yaml](developer.yaml) | developer | API keys, webhooks, secrets vault, verifiable credentials, auth hooks, agents |
| [operations.yaml](operations.yaml) | operations | Audit, analytics, billing, GDPR, email templates, retention, log sinks (SIEM), notifications, health |

Each file carries its own `components` (the transitive `$ref` closure of what its
paths use) plus the shared `securitySchemes`, so every file validates standalone.

## Adding or changing routes

1. Edit the file for the relevant bounded context (match the operation's `tags`).
2. The CI guard ([`internal/bootstrap/openapi_coverage_test.go`](../../internal/bootstrap/openapi_coverage_test.go))
   reads the **union** of these files and walks the exact production mount
   helpers. It fails on undocumented routes, stale operations, and API-auth
   security mismatches.

## Tag order and the developer journey

Operations are grouped by `tag`, and the **order of path items in each file is
intentional**. The api.qeet.in portal (Scalar) orders the tags within a product by
the **first appearance of each tag in document order** — it does *not* read the
root `tags:` array order or any `x-*` ordering hint. Each file's paths are therefore
laid out to follow an onboarding journey, and its top-level `tags:` array is kept in
the same order for readability:

- **auth**: Auth → Passkeys → MFA → RBAC → ABAC → ReBAC → AuthZEN → Auth Policy → Policy → IP Rules → Threats
- **management**: Tenants → Domains → Users → Verification → Groups → Invites → Branding
- **federation**: OIDC → Social → SAML → LDAP → Directory → SCIM → Admin Portal
- **developer**: API Keys → Agents → Credentials → Auth Hooks → Webhooks → Secrets → Token Vault
- **operations**: Health → Activity → Analytics → Search → Audit → Compliance → Data Retention → GDPR → Log Sinks → Notifications → Rate Limits → Email Templates → Qeet AI → Billing → Entitlements → Sales

When adding an operation, place it next to the other paths of its tag so the journey
order is preserved, and declare the tag (with a `description`) in the top-level
`tags:` array. `bun run validate:specs` in the qeet-apis repo warns on undeclared,
unused, or undescribed tags.

## Tooling

These files are split by bounded context. A consumer that wants one document merges
them itself — the qeet-apis reference site does so in `scripts/sync-specs.mjs`.
