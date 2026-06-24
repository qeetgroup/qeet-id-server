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
2. The CI guard ([`platform/api/rest/openapi_coverage_test.go`](../../platform/api/rest/openapi_coverage_test.go))
   reads the **union** of these files and fails the build if any mounted route is
   undocumented — keep it green.

## Tooling

These files are split by bounded context; tools that want a single document merge
them on the fly:

```bash
# Merge all five into one document (stdout) — used by codegen, Swagger UI, etc.
go run ./tools/openapi-split merge

# Verify each file is self-contained (no dangling $ref, no stray YAML aliases)
go run ./tools/openapi-split verify
```

SDK type generation ([`tools/codegen/openapi-gen.sh`](../../tools/codegen/openapi-gen.sh))
uses the merge step automatically.
