# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 minor versions may include breaking changes — they will be called out explicitly under a **Breaking** subsection.

---

## [Unreleased]

> **Status: pre-1.0 — no versioned release has been published yet.** An earlier draft of this file dated a
> `1.0.0` release on 2026-06-22; that was premature — nothing has actually been launched. The first `1.0.0`
> tag will be cut at the initial public GA. **[ROADMAP.md](./ROADMAP.md) is the single source of truth for
> current shipped-vs-planned status;** this file records what lands in each release from that tag onward. (A
> still-earlier pre-implementation snapshot here — WebAuthn/SAML/SCIM/billing as 501s, HS256, bcrypt — no
> longer matches the codebase; all of those have since shipped.)

The changes below are the work staged for that first release.

### Security

Remediation of the 2026-09-05 production audit
([docs/PRODUCTION-AUDIT-2026-09-05.md](./docs/PRODUCTION-AUDIT-2026-09-05.md)),
plus follow-up fixes from reviewing that remediation. Migrations `0097`–`0106`.

* **authz:** route policy is default-deny for users *and* machine principals; the
  live router must have exact policy coverage (enforced by test). Machine
  credentials now need an exact scope match — `0105` writes the access existing
  credentials already had into their scope arrays so nothing silently breaks.
* **tenancy:** user creation, legacy OIDC client registration, OAuth
  authorization, and GDPR request/purge paths all derive or verify tenant scope
  instead of trusting a request body; composite FKs back it at the schema level.
* **keys:** the runtime signing-key rotation endpoint is gone. Keys live in a
  shared, envelope-encrypted registry with two-phase activation
  ([docs/JWT-KEY-ROTATION.md](./docs/JWT-KEY-ROTATION.md)).
* **federation:** SAML AuthnRequest correlation and response/assertion replay
  IDs are consumed atomically; Apple ID tokens get full JWKS/claims validation;
  public OAuth clients must use S256 PKCE; social auto-linking to an existing
  account requires a verified email.
* **egress:** tenant-configured outbound calls go through a shared policy that
  rejects private, loopback, metadata and DNS-rebinding destinations.
* **secrets:** reversible domain secrets use context-bound envelope ciphertext
  (tenant + purpose + resource); comparison-only credentials are hashed.
* **mfa:** per-challenge and per-account attempt budgets, shared across replicas.
* **admin portal:** one-time fragment links exchange for scoped HttpOnly
  sessions; capability tokens no longer appear in URLs or logs.
* **social login:** adopting an existing account requires both a verified email
  *and* that the account already belongs to the tenant being signed in to —
  emails are globally unique, so without the second check a tenant's own IdP
  could assert another tenant's user's address and be handed their identity.
* **csrf:** exemptions are exact/prefix/single-segment rather than bare
  prefixes, which had been exempting authenticated mutations mounted under a
  public feature area (`POST /v1/social/providers`,
  `POST /v1/oauth/bc-authorize/decision`).
* **scim:** user create/replace/patch/delete now write audit and outbox
  evidence in the mutation transaction, and bound their request bodies.
* **qeet ai:** tenant provider keys are envelope-sealed against their tenant, so
  ciphertext can no longer be transplanted between rows; BYOK `base_url` goes
  through the shared egress policy.
* **users:** an admin password reset revokes the target's sessions and records
  the act, matching self-service password change.

#### Breaking

* **Machine credentials** must carry explicit scopes. `0105` backfills existing
  rows with a compatibility set — review and narrow it.
* **Admin portal:** `0102` revokes every outstanding link (they predate the
  fragment-only format and may have leaked through path logs). The API moved
  from `/v1/admin-portal/{token}/…` to a cookie session established by
  `POST /v1/admin-portal/session`, and the CSRF exemption is gone, so callers
  must send `X-CSRF-Token`. Links are now single-use, default TTL 1h (was 24h).
* **Public OAuth clients** must send a valid S256 `code_challenge`.
* **IdP-initiated SAML** is refused unless the connection sets
  `allow_idp_initiated` (new in `0106`); replay protection applies either way.
* **OAuth redirect URIs** are validated at registration: HTTPS, HTTP loopback,
  or an RFC 8252 reverse-DNS private-use scheme.
* **Session listing** is cursor-paginated instead of hard-capped at 100.

### Features

* **deploy:** add deploy/release layer (Compose, Helm, migrate image, AWS KMS, CI→CD) ([3e176c5](https://github.com/qeetgroup/qeet-id-server/commit/3e176c59a8fca6bbf1bf614a4c97b0bdab5a8dfb))
* **frontend:** adopt @qeetrix/ui across admin, web, and docs ([c32b8b9](https://github.com/qeetgroup/qeet-id-server/commit/c32b8b9b7d152b1aeb94d8424ac3d7ef9d7667dd))


### Bug Fixes

* **api:** align Postman baseUrl to port 4000 (matches standardized backend port) ([202aa84](https://github.com/qeetgroup/qeet-id-server/commit/202aa845ad0d527367d32c0e1a454b9cfd2b12f3))
* **deploy:** assemble DB_URL via interpolation; drop distroless-incompatible healthcheck ([94da569](https://github.com/qeetgroup/qeet-id-server/commit/94da5697a3c1f8f0fc48a3418965d8b2c7c5b9b9))
* **oidc:** derive issuer/discovery scheme from X-Forwarded-Proto ([f03b6dd](https://github.com/qeetgroup/qeet-id-server/commit/f03b6dd193fd94b1e162e0f8364575385d6937bd))
* **repo:** correct doc drift, dead docs targets, eslint login wiring, image license ([c250c60](https://github.com/qeetgroup/qeet-id-server/commit/c250c603d4fdf9dc8af5ddb91b6a381992436e4a))


### Refactoring

* **backend:** unify SAML error envelope, bound SMTP, log encode errors ([2fed216](https://github.com/qeetgroup/qeet-id-server/commit/2fed21639b4318adafb729fda113d5de026f080f))
* rename qeet-identity → qeet-id across module path, URLs, names ([9c438ef](https://github.com/qeetgroup/qeet-id-server/commit/9c438ef523875ecd5a9ee2692ac67b762d5f3b99))
