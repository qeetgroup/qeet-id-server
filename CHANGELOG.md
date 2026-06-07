# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pre-1.0 minor versions may include breaking changes — they will be called out explicitly under a **Breaking** subsection.

---

## 1.0.0 (2026-06-07)


### Features

* **deploy:** add deploy/release layer (Compose, Helm, migrate image, AWS KMS, CI→CD) ([3e176c5](https://github.com/qeetgroup/qeet-id/commit/3e176c59a8fca6bbf1bf614a4c97b0bdab5a8dfb))
* **frontend:** adopt @qeetrix/ui across admin, web, and docs ([c32b8b9](https://github.com/qeetgroup/qeet-id/commit/c32b8b9b7d152b1aeb94d8424ac3d7ef9d7667dd))


### Bug Fixes

* **api:** align Postman baseUrl to port 4000 (matches standardized backend port) ([202aa84](https://github.com/qeetgroup/qeet-id/commit/202aa845ad0d527367d32c0e1a454b9cfd2b12f3))
* **deploy:** assemble DB_URL via interpolation; drop distroless-incompatible healthcheck ([94da569](https://github.com/qeetgroup/qeet-id/commit/94da5697a3c1f8f0fc48a3418965d8b2c7c5b9b9))
* **oidc:** derive issuer/discovery scheme from X-Forwarded-Proto ([f03b6dd](https://github.com/qeetgroup/qeet-id/commit/f03b6dd193fd94b1e162e0f8364575385d6937bd))
* **repo:** correct doc drift, dead docs targets, eslint login wiring, image license ([c250c60](https://github.com/qeetgroup/qeet-id/commit/c250c603d4fdf9dc8af5ddb91b6a381992436e4a))


### Refactoring

* **backend:** unify SAML error envelope, bound SMTP, log encode errors ([2fed216](https://github.com/qeetgroup/qeet-id/commit/2fed21639b4318adafb729fda113d5de026f080f))
* rename qeet-identity → qeet-id across module path, URLs, names ([9c438ef](https://github.com/qeetgroup/qeet-id/commit/9c438ef523875ecd5a9ee2692ac67b762d5f3b99))

## [Unreleased]

### Added
- Initial monorepo scaffold: backend (Go) + frontend (3 apps + shared UI) + documents.
- Backend modules: `auth`, `user`, `tenant`, `rbac`, `verification`, `recovery`, `invite`, `mfa`, `oidc`, `passkey`, `social`, `apikey`, `principal`, `audit`, `policy`, `branding`, `gdpr`, `webhook`, `group`.
- Database migrations 0001–0021 across `platform`, `tenant`, `user`, `auth`, `rbac`, `audit` schemas.
- Admin dashboard (`qeetid-admin`) with sign-in / sign-up and `/dashboard` analytics view; placeholder routing for remaining ~38 screens.
- Marketing site (`qeetid-web`) — homepage, features, pricing, security, customers, contact.
- Docs site (`qeetid-docs`) — 32 MDX pages covering authentication, API, SDKs, RBAC, MFA, sessions, audit, webhooks, rate limits.
- Shared UI component library (`@qeetid/ui`) — 20 shadcn-style primitives.
- Root project conventions: README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG, .editorconfig.
- Implementation traceability documents under [documents/](./documents/).

### Known gaps (see [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md))
- WebAuthn passkey ceremony returns 501 (storage layer ready).
- Social OAuth `/start` and `/callback` return 501 (provider config + identity-linking ready).
- OAuth 2.0 Authorization Code grant + OIDC ID-token issuance not yet wired.
- SAML 2.0 (SP + IdP) and SCIM 2.0 not implemented.
- Production JWT signing uses HS256 with a static key (intended: RS256/ES256 with 90-day JWKS rotation).
- Password hashing uses bcrypt (intended: Argon2id).
- Email and SMS senders are `LogSender` only — no real provider wired.
- Billing / Stripe entirely absent.

---

## [0.1.0] — planned MVP "Foundation"

Target: month 15 per upstream roadmap. Will land:

- WebAuthn passkey ceremony (FIDO Alliance FIDO2 Server certified)
- Social OAuth: Google, GitHub, Microsoft, Apple
- OAuth 2.0 Authorization Code + PKCE; OIDC ID-token issuance; OpenID Foundation Basic OP certified
- SAML 2.0 SP and IdP, Single Logout, integration with Entra ID / Okta / Google Workspace
- SCIM 2.0 Users + Groups + ServiceProviderConfig + ResourceTypes + Schemas
- Admin dashboard: Users, Roles, Audit, Applications, Webhooks, API Keys, Branding, Tenant Profile screens
- Argon2id password hashing, RS256/ES256 JWT signing with 90-day key rotation
- Real email (SendGrid) and SMS (Twilio) providers
- GDPR data export + complete erasure pipeline + consent records
- Stripe billing — Free / Growth / Enterprise tiers, MAU metering
- SOC 2 Type I attestation, GDPR DPA, Trust Center
- CI/CD via GitHub Actions; OpenTelemetry tracing; Prometheus metrics

See [documents/GAP-ANALYSIS.md](./documents/GAP-ANALYSIS.md) for the prioritized punch list and 12-week sequencing.
